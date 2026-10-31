//! [`KmsClient`] over the official `aws-sdk-kms` client (feature `sdk`).
//!
//! The caller builds the `aws_sdk_kms::Client` (region, credentials, HTTP
//! client, timeouts); this crate does not read credentials. Calls run on a
//! small runtime owned by the adapter and the caller waits on a channel, so
//! `sign_raw` can be called from synchronous code, including tokio
//! `spawn_blocking` threads, without nesting runtimes.

use crate::{KmsCallError, KmsClient, KmsPublicKey};
use aws_sdk_kms::{
    error::{ProvideErrorMetadata, SdkError},
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use std::{sync::mpsc, time::Duration};

/// Error codes that mean "try again later"; every other service error is a
/// refusal.
const TRANSIENT_CODES: &[&str] = &[
    "DependencyTimeoutException",
    "KMSInternalException",
    "KeyUnavailableException",
    "ThrottlingException",
    "RequestLimitExceeded",
    "LimitExceededException",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "InternalFailure",
    "RequestTimeout",
    "RequestTimeoutException",
];

/// Classifies an SDK error without looking at its message.
pub fn classify<E, R>(error: &SdkError<E, R>) -> KmsCallError
where
    E: ProvideErrorMetadata,
{
    match error {
        SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) | SdkError::ResponseError(_) => {
            KmsCallError::Unavailable
        }
        SdkError::ServiceError(service) => classify_code(service.err().code()),
        // Construction failures are local and permanent.
        _ => KmsCallError::Rejected,
    }
}

/// Classifies an AWS error code.
pub fn classify_code(code: Option<&str>) -> KmsCallError {
    match code {
        Some(code) if TRANSIENT_CODES.contains(&code) => KmsCallError::Unavailable,
        _ => KmsCallError::Rejected,
    }
}

/// Owns a one-thread tokio runtime. Keep it for the life of the process
/// (inside the signer): like any tokio runtime, it must not be dropped from
/// within an async context.
pub struct AwsSdkKmsClient {
    client: aws_sdk_kms::Client,
    runtime: tokio::runtime::Runtime,
    timeout: Duration,
}

impl std::fmt::Debug for AwsSdkKmsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsSdkKmsClient")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl AwsSdkKmsClient {
    /// `timeout` bounds each call, including SDK retries; when it expires
    /// the call is reported as [`KmsCallError::Unavailable`].
    pub fn new(client: aws_sdk_kms::Client, timeout: Duration) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("praetore-aws-kms")
            .enable_all()
            .build()?;
        Ok(Self {
            client,
            runtime,
            timeout,
        })
    }

    fn run<T: Send + 'static>(
        &self,
        future: impl Future<Output = Result<T, KmsCallError>> + Send + 'static,
    ) -> Result<T, KmsCallError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.runtime.spawn(async move {
            let _ = sender.send(future.await);
        });
        receiver
            .recv_timeout(self.timeout)
            .unwrap_or(Err(KmsCallError::Unavailable))
    }
}

impl KmsClient for AwsSdkKmsClient {
    fn get_public_key(&self, key_id: &str) -> Result<KmsPublicKey, KmsCallError> {
        let request = self.client.get_public_key().key_id(key_id);
        self.run(async move {
            let output = request.send().await.map_err(|error| classify(&error))?;
            Ok(KmsPublicKey {
                key_spec: output.key_spec().map(|spec| spec.as_str().to_owned()),
                key_usage: output.key_usage().map(|usage| usage.as_str().to_owned()),
                signing_algorithms: output
                    .signing_algorithms()
                    .iter()
                    .map(|algorithm| algorithm.as_str().to_owned())
                    .collect(),
                public_key_der: output
                    .public_key()
                    .map(|blob| blob.as_ref().to_vec())
                    .unwrap_or_default(),
            })
        })
    }

    fn sign_ed25519_raw(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, KmsCallError> {
        let request = self
            .client
            .sign()
            .key_id(key_id)
            .message(Blob::new(message.to_vec()))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512);
        self.run(async move {
            let output = request.send().await.map_err(|error| classify(&error))?;
            if output.signing_algorithm() != Some(&SigningAlgorithmSpec::Ed25519Sha512) {
                return Err(KmsCallError::Rejected);
            }
            output
                .signature()
                .map(|blob| blob.as_ref().to_vec())
                .ok_or(KmsCallError::Rejected)
        })
    }
}

#[cfg(test)]
mod tests {
    //! The real SDK client, serializing real requests, against a local fake
    //! HTTP connector: no network and no AWS credentials (the static test
    //! credentials below are not real).

    use super::*;
    use crate::{AwsKmsSigner, ED25519_SPKI_PREFIX};
    use aws_sdk_kms::config::{BehaviorVersion, Credentials, Region};
    use aws_smithy_runtime_api::client::{
        http::{
            HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings,
            SharedHttpConnector,
        },
        orchestrator::{HttpRequest, HttpResponse},
        runtime_components::RuntimeComponents,
    };
    use aws_smithy_types::body::SdkBody;
    use praetore_core::{LocalSigner, Signer};
    use std::sync::{Arc, Mutex};

    const KEY_ARN: &str =
        "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    #[derive(Clone, Copy)]
    enum Mode {
        Ok,
        Throttled,
        AccessDenied,
    }

    /// Answers GetPublicKey and Sign like KMS, signing with a local key.
    #[derive(Clone)]
    struct FakeKms {
        key: Arc<LocalSigner>,
        mode: Arc<Mutex<Mode>>,
        requests: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    fn b64(bytes: &[u8]) -> String {
        aws_smithy_types::base64::encode(bytes)
    }

    impl FakeKms {
        fn respond(&self, request: &HttpRequest) -> HttpResponse {
            let target = request
                .headers()
                .get("x-amz-target")
                .unwrap_or_default()
                .to_owned();
            assert!(request.headers().get("authorization").is_some());
            let body: serde_json::Value =
                serde_json::from_slice(request.body().bytes().unwrap()).unwrap();
            self.requests.lock().unwrap().push(body.clone());
            let (status, payload) = match *self.mode.lock().unwrap() {
                Mode::Throttled => (
                    400,
                    serde_json::json!({"__type": "ThrottlingException", "message": "Rate exceeded"}),
                ),
                Mode::AccessDenied => (
                    400,
                    serde_json::json!({"__type": "AccessDeniedException", "message": "denied"}),
                ),
                Mode::Ok => match target.as_str() {
                    "TrentService.GetPublicKey" => {
                        let mut der = ED25519_SPKI_PREFIX.to_vec();
                        der.extend_from_slice(&self.key.verifying_key().as_bytes());
                        (
                            200,
                            serde_json::json!({
                                "KeyId": KEY_ARN,
                                "KeySpec": "ECC_NIST_EDWARDS25519",
                                "KeyUsage": "SIGN_VERIFY",
                                "SigningAlgorithms": ["ED25519_SHA_512", "ED25519_PH_SHA_512"],
                                "PublicKey": b64(&der),
                            }),
                        )
                    }
                    "TrentService.Sign" => {
                        assert_eq!(body["MessageType"], "RAW");
                        assert_eq!(body["SigningAlgorithm"], "ED25519_SHA_512");
                        let message =
                            aws_smithy_types::base64::decode(body["Message"].as_str().unwrap())
                                .unwrap();
                        let signature = self.key.sign_raw(&message).unwrap();
                        (
                            200,
                            serde_json::json!({
                                "KeyId": KEY_ARN,
                                "SigningAlgorithm": "ED25519_SHA_512",
                                "Signature": b64(&signature),
                            }),
                        )
                    }
                    other => panic!("unexpected operation {other}"),
                },
            };
            let mut response = HttpResponse::new(
                status.try_into().unwrap(),
                SdkBody::from(payload.to_string()),
            );
            response
                .headers_mut()
                .insert("content-type", "application/x-amz-json-1.1");
            response
        }
    }

    impl std::fmt::Debug for FakeKms {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("FakeKms")
        }
    }

    impl HttpConnector for FakeKms {
        fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
            let response = self.respond(&request);
            HttpConnectorFuture::ready(Ok(response))
        }
    }

    impl HttpClient for FakeKms {
        fn http_connector(
            &self,
            _settings: &HttpConnectorSettings,
            _components: &RuntimeComponents,
        ) -> SharedHttpConnector {
            SharedHttpConnector::new(self.clone())
        }
    }

    fn client(fake: &FakeKms) -> AwsSdkKmsClient {
        let config = aws_sdk_kms::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("eu-west-1"))
            .credentials_provider(Credentials::new(
                "AKIDPRAETORETESTONLY",
                "not-a-real-secret",
                None,
                None,
                "praetore-test",
            ))
            .http_client(fake.clone())
            .retry_config(aws_sdk_kms::config::retry::RetryConfig::disabled())
            .build();
        AwsSdkKmsClient::new(
            aws_sdk_kms::Client::from_conf(config),
            Duration::from_secs(10),
        )
        .unwrap()
    }

    fn fake() -> FakeKms {
        FakeKms {
            key: Arc::new(LocalSigner::from_secret_bytes(&[0x5d; 32])),
            mode: Arc::new(Mutex::new(Mode::Ok)),
            requests: Arc::default(),
        }
    }

    #[test]
    fn the_sdk_adapter_sends_raw_ed25519_requests_and_signatures_verify() {
        let fake = fake();
        let signer = AwsKmsSigner::new(Arc::new(client(&fake)), KEY_ARN, None).unwrap();
        assert_eq!(signer.verifying_key(), fake.key.verifying_key());
        let signature =
            praetore_core::signer::sign_exact(&signer, b"PRAETORE_TEST\0message").unwrap();
        fake.key
            .verifying_key()
            .verify_domain_message(b"", b"PRAETORE_TEST\0message", &signature)
            .unwrap();
        let requests = fake.requests.lock().unwrap();
        // GetPublicKey, the self-test Sign, and this Sign.
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0]["KeyId"], KEY_ARN);
        assert!(
            requests[1..]
                .iter()
                .all(|request| request["MessageType"] == "RAW")
        );
    }

    #[test]
    fn sdk_errors_are_classified_and_called_from_a_tokio_blocking_thread() {
        let fake = fake();
        let signer = Arc::new(AwsKmsSigner::new(Arc::new(client(&fake)), KEY_ARN, None).unwrap());
        // As the gateway calls it: inside spawn_blocking of another runtime.
        let outer = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap();
        for (mode, expected) in [
            (
                Mode::Throttled,
                Err(praetore_core::SignerError::Unavailable),
            ),
            (
                Mode::AccessDenied,
                Err(praetore_core::SignerError::Rejected),
            ),
        ] {
            *fake.mode.lock().unwrap() = mode;
            let signer = signer.clone();
            let result = outer
                .block_on(async move {
                    tokio::task::spawn_blocking(move || {
                        praetore_core::signer::sign_exact(signer.as_ref(), b"m").map(|_| ())
                    })
                    .await
                })
                .unwrap();
            assert_eq!(result, expected);
        }
        *fake.mode.lock().unwrap() = Mode::Ok;
        assert!(praetore_core::signer::sign_exact(signer.as_ref(), b"m").is_ok());
    }

    #[test]
    fn error_codes_are_classified_without_reading_messages() {
        assert_eq!(
            classify_code(Some("ThrottlingException")),
            KmsCallError::Unavailable
        );
        assert_eq!(
            classify_code(Some("KMSInternalException")),
            KmsCallError::Unavailable
        );
        for code in [
            "AccessDeniedException",
            "DisabledException",
            "KMSInvalidStateException",
            "NotFoundException",
            "InvalidKeyUsageException",
        ] {
            assert_eq!(classify_code(Some(code)), KmsCallError::Rejected);
        }
        assert_eq!(classify_code(None), KmsCallError::Rejected);
    }
}

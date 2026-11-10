//! Which [`ExecMode`] the service's HTTP API runs.
//!
//! Cooperative execution, where the agent performs an authorized effect
//! itself, is refused by default with every adapter. It is accepted only with
//! the local-demo adapter and the explicit development flag
//! [`DEV_COOPERATIVE_EXEC_ENV`]`=1`, a mode that gives no guarantee about who
//! performs an effect. No request header selects or enables a mode.

use praetore_gateway::http_api::{ExecMode, HttpOptions};

/// Development flag of the local-demo adapter. Only `1` enables the
/// cooperative mode; unset or `0` keeps the default.
pub const DEV_COOPERATIVE_EXEC_ENV: &str = "PRAETORE_GATEWAY_DEV_COOPERATIVE_EXEC";

/// Logged at startup when the development cooperative mode is on.
pub const DEV_COOPERATIVE_EXEC_WARNING: &str = "development cooperative mode (PRAETORE_GATEWAY_DEV_COOPERATIVE_EXEC=1): agents may perform authorized effects themselves, outside the gateway; this mode gives no guarantee about who performs an effect; do not use it outside development";

/// The HTTP options for an adapter. `production_adapter` is the `http` or
/// `sandbox` adapter, whose dispatcher performs the effects; the flag is
/// refused there. `dev_flag` is the raw value of [`DEV_COOPERATIVE_EXEC_ENV`].
pub fn select_http_options(
    production_adapter: bool,
    dev_flag: Option<&str>,
) -> Result<HttpOptions, Box<dyn std::error::Error>> {
    let development = match dev_flag {
        None | Some("0") => false,
        Some("1") => true,
        Some(_) => return Err(format!("{DEV_COOPERATIVE_EXEC_ENV} must be 0 or 1").into()),
    };
    let exec_mode = match (production_adapter, development) {
        (true, true) => {
            return Err(format!(
                "{DEV_COOPERATIVE_EXEC_ENV}=1 is accepted only with the local-demo adapter"
            )
            .into());
        }
        (true, false) => ExecMode::GatewayEffects,
        (false, true) => ExecMode::DevelopmentCooperative,
        (false, false) => ExecMode::GatewayOnly,
    };
    Ok(HttpOptions { exec_mode })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooperative_execution_is_refused_unless_the_local_demo_sets_the_flag() {
        let mode = |production, flag| select_http_options(production, flag).map(|o| o.exec_mode);
        assert_eq!(mode(false, None).unwrap(), ExecMode::GatewayOnly);
        assert_eq!(mode(false, Some("0")).unwrap(), ExecMode::GatewayOnly);
        assert_eq!(mode(true, None).unwrap(), ExecMode::GatewayEffects);
        assert_eq!(mode(true, Some("0")).unwrap(), ExecMode::GatewayEffects);
        assert_eq!(
            mode(false, Some("1")).unwrap(),
            ExecMode::DevelopmentCooperative
        );
        assert!(mode(true, Some("1")).is_err());
        for bad in ["", "true", "yes", "cooperative", " 1", "2"] {
            assert!(mode(false, Some(bad)).is_err(), "{bad:?}");
        }
    }
}

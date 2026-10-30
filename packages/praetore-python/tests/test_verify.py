from pathlib import Path
import unittest

import praetore


FIXTURES = Path(__file__).parent / "fixtures"


class EvidenceVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = (FIXTURES / "evidence-valid.json").read_text(encoding="utf-8")
        self.attester_pin = (FIXTURES / "attester-public-key.hex").read_text(
            encoding="ascii"
        ).strip()
        self.tampered = (FIXTURES / "evidence-tampered.json").read_text(
            encoding="utf-8"
        )

    def test_integrity_accepts_valid_evidence(self) -> None:
        self.assertTrue(praetore.verify_evidence_integrity(self.evidence))

    def test_integrity_rejects_tampered_evidence(self) -> None:
        self.assertFalse(praetore.verify_evidence_integrity(self.tampered))

    def test_attester_signature_accepts_valid_evidence(self) -> None:
        self.assertTrue(
            praetore.verify_evidence_attester_signature(
                self.evidence, self.attester_pin
            )
        )

    def test_attester_signature_rejects_tampered_evidence_and_wrong_key(self) -> None:
        self.assertFalse(
            praetore.verify_evidence_attester_signature(
                self.tampered, self.attester_pin
            )
        )
        self.assertFalse(
            praetore.verify_evidence_attester_signature(self.evidence, "00" * 32)
        )

    def test_malformed_json_fails_closed(self) -> None:
        self.assertFalse(praetore.verify_evidence_integrity("{"))
        self.assertFalse(
            praetore.verify_evidence_attester_signature("{", self.attester_pin)
        )


class GatewayReceiptVerificationTests(unittest.TestCase):
    KEY_ID = "test-execution-attester-v1"

    def setUp(self) -> None:
        self.v3 = (FIXTURES / "receipt-v3-crash-recovered.json").read_text(
            encoding="utf-8"
        )
        self.v2 = (FIXTURES / "receipt-v2-confirmed.json").read_text(encoding="utf-8")
        self.pin = (FIXTURES / "execution-attester-public-key.hex").read_text(
            encoding="ascii"
        ).strip()
        self.evidence_pin = (
            FIXTURES / "receipt-evidence-attester-public-key.hex"
        ).read_text(encoding="ascii").strip()

    def verify(self, receipt: str) -> bool:
        return praetore.verify_gateway_receipt(
            receipt, self.pin, self.KEY_ID, self.evidence_pin
        )

    def test_accepts_v3_with_reason_and_v2(self) -> None:
        self.assertIn('"schema_version":3', self.v3)
        self.assertIn('"not_dispatched_reason":"crash_recovered"', self.v3)
        self.assertTrue(self.verify(self.v3))
        self.assertTrue(self.verify(self.v2))

    def test_accepts_v1_and_rejects_tampered_copy(self) -> None:
        v1 = (FIXTURES / "receipt-v1-confirmed.json").read_text(encoding="utf-8")
        self.assertIn('"schema_version":1', v1)
        self.assertTrue(self.verify(v1))
        tampered = v1.replace('"confirmed"', '"failed"', 1)
        self.assertNotEqual(tampered, v1)
        self.assertFalse(self.verify(tampered))

    def test_rejects_unknown_reason(self) -> None:
        forged = self.v3.replace('"crash_recovered"', '"operator_override"')
        self.assertNotEqual(forged, self.v3)
        self.assertFalse(self.verify(forged))

    def test_rejects_swapped_or_missing_reason(self) -> None:
        swapped = self.v3.replace('"crash_recovered"', '"approval_expired"')
        self.assertFalse(self.verify(swapped))
        missing = self.v3.replace(',"not_dispatched_reason":"crash_recovered"', "")
        self.assertNotEqual(missing, self.v3)
        self.assertFalse(self.verify(missing))

    def test_rejects_wrong_key_and_malformed_input(self) -> None:
        self.assertFalse(
            praetore.verify_gateway_receipt(
                self.v3, "00" * 32, self.KEY_ID, self.evidence_pin
            )
        )
        self.assertFalse(
            praetore.verify_gateway_receipt(
                self.v3, self.pin, "other-key", self.evidence_pin
            )
        )
        self.assertFalse(self.verify("{"))

    def test_rejects_forged_missing_or_foreign_evidence_attester_signature(
        self,
    ) -> None:
        import json

        for name in (
            "receipt-v1-confirmed.json",
            "receipt-v2-confirmed.json",
            "receipt-v3-crash-recovered.json",
        ):
            original = (FIXTURES / name).read_text(encoding="utf-8")
            self.assertTrue(self.verify(original), name)
            receipt = json.loads(original)
            receipt["evidence"]["attester_signature"] = "0" * 128
            self.assertFalse(self.verify(json.dumps(receipt)), name)
            signature = json.loads(original)["evidence"]["attester_signature"]
            receipt["evidence"]["attester_signature"] = signature.upper()
            self.assertFalse(self.verify(json.dumps(receipt)), name)
            receipt["evidence"]["attester_signature"] = signature[:126]
            self.assertFalse(self.verify(json.dumps(receipt)), name)
            receipt["evidence"]["attester_signature"] = None
            self.assertFalse(self.verify(json.dumps(receipt)), name)
            other = (FIXTURES / "attester-public-key.hex").read_text(
                encoding="ascii"
            ).strip()
            self.assertFalse(
                praetore.verify_gateway_receipt(original, self.pin, self.KEY_ID, other),
                name,
            )


class LegacyEvidenceVerificationTests(unittest.TestCase):
    """Receipts whose evidence predates ``decided_by`` (schema v1-v3) keep
    verifying unchanged; current fixtures carry evidence schema v4."""

    KEY_ID = "test-execution-attester-v1"
    LEGACY = FIXTURES / "legacy-evidence"
    RECEIPTS = (
        "receipt-v1-confirmed.json",
        "receipt-v2-confirmed.json",
        "receipt-v3-crash-recovered.json",
    )

    def setUp(self) -> None:
        read_hex = lambda name: (FIXTURES / name).read_text(encoding="ascii").strip()
        self.attester_pin = read_hex("attester-public-key.hex")
        self.pin = read_hex("execution-attester-public-key.hex")
        self.evidence_pin = read_hex("receipt-evidence-attester-public-key.hex")

    def verify(self, receipt: str) -> bool:
        return praetore.verify_gateway_receipt(
            receipt, self.pin, self.KEY_ID, self.evidence_pin
        )

    def test_legacy_evidence_still_verifies(self) -> None:
        import json

        legacy = (self.LEGACY / "evidence-valid.json").read_text(encoding="utf-8")
        self.assertEqual(json.loads(legacy)["evidence_schema_version"], 1)
        self.assertNotIn("decided_by", legacy)
        self.assertTrue(praetore.verify_evidence_integrity(legacy))
        self.assertTrue(
            praetore.verify_evidence_attester_signature(legacy, self.attester_pin)
        )
        tampered = (self.LEGACY / "evidence-tampered.json").read_text(encoding="utf-8")
        self.assertFalse(praetore.verify_evidence_integrity(tampered))

    def test_current_evidence_is_v4_with_decided_by(self) -> None:
        import json

        current = json.loads(
            (FIXTURES / "evidence-valid.json").read_text(encoding="utf-8")
        )
        self.assertEqual(current["evidence_schema_version"], 4)
        self.assertIn("decided_by", current["decision"])
        for name in self.RECEIPTS:
            receipt = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
            self.assertEqual(receipt["evidence"]["evidence_schema_version"], 4, name)
            self.assertIn("decided_by", receipt["evidence"]["decision"], name)

    def test_legacy_receipts_still_verify_and_reject_tampering(self) -> None:
        import json

        for name in self.RECEIPTS:
            original = (self.LEGACY / name).read_text(encoding="utf-8")
            receipt = json.loads(original)
            self.assertLess(receipt["evidence"]["evidence_schema_version"], 4, name)
            self.assertNotIn("decided_by", receipt["evidence"]["decision"], name)
            self.assertTrue(self.verify(original), name)
            tampered = original.replace('"confirmed"', '"failed"', 1)
            if tampered != original:
                self.assertFalse(self.verify(tampered), name)
            receipt["evidence"]["decision"]["decided_by"] = {
                "kind": "default_deny"
            }
            self.assertFalse(self.verify(json.dumps(receipt)), name)

    def test_decided_by_tampering_fails_closed(self) -> None:
        import json

        for name in self.RECEIPTS:
            original = (FIXTURES / name).read_text(encoding="utf-8")
            for forged in (
                None,
                {"kind": "default_deny"},
                {"kind": "rule", "rule_id": "some-other-rule"},
                {"kind": "operator_override"},
                {"kind": "rule", "rule_id": "require-human-approval", "x": 1},
            ):
                receipt = json.loads(original)
                if forged is None:
                    del receipt["evidence"]["decision"]["decided_by"]
                else:
                    receipt["evidence"]["decision"]["decided_by"] = forged
                self.assertFalse(self.verify(json.dumps(receipt)), (name, forged))


if __name__ == "__main__":
    unittest.main()

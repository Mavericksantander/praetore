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


if __name__ == "__main__":
    unittest.main()

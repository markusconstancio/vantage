import unittest
from pathlib import Path

from vantage.osint.assess import OsintAgent
from vantage.osint.persona import Persona
from vantage.osint.scoring import MAX_RAW, band, score_persona

PERSONA = Path(__file__).resolve().parents[1] / "personas" / "jordan-rivera.yaml"


class BandTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(band(80), "Critical")
        self.assertEqual(band(73), "High")
        self.assertEqual(band(47), "Moderate")
        self.assertEqual(band(10), "Low")

    def test_max_raw(self):
        self.assertEqual(MAX_RAW, 60)


class PersonaScoreTests(unittest.TestCase):
    def setUp(self):
        self.persona = Persona.load(PERSONA)

    def test_before_score_matches_manual(self):
        score = score_persona(self.persona)
        self.assertEqual(score.raw, 44)
        self.assertEqual(score.score, 73)
        self.assertEqual(score.band, "High")

    def test_after_remediation_drops_to_moderate(self):
        remediated = self.persona.with_posture(
            mfa_enabled=True, passwords_unique=True, phone_public=False
        )
        score = score_persona(remediated)
        self.assertEqual(score.raw, 28)
        self.assertEqual(score.score, 47)
        self.assertEqual(score.band, "Moderate")

    def test_remediation_does_not_mutate_original(self):
        _ = self.persona.with_posture(mfa_enabled=True)
        self.assertFalse(self.persona.posture.mfa_enabled)

    def test_individual_before_ratings(self):
        by = {f.factor: f.rating for f in score_persona(self.persona).factors}
        self.assertEqual(by["breach_exposure"], 2)
        self.assertEqual(by["credential_reuse"], 3)
        self.assertEqual(by["identity_exposure"], 2)
        self.assertEqual(by["contact_exposure"], 2)
        self.assertEqual(by["pretext_material"], 2)
        self.assertEqual(by["account_discoverability"], 2)


class AssessTests(unittest.TestCase):
    def setUp(self):
        self.assessment = OsintAgent().assess(Persona.load(PERSONA))

    def test_scenarios_present(self):
        names = [s["name"] for s in self.assessment["scenarios"]]
        self.assertTrue(any("Credential stuffing" in n for n in names))
        self.assertTrue(any("Spear-phishing" in n for n in names))

    def test_remediation_present(self):
        recs = " ".join(self.assessment["remediation"]).lower()
        self.assertIn("mfa", recs)
        self.assertIn("password", recs)

    def test_no_breach_passwords_leaked_in_output(self):
        # Output must record breach fact/metadata only, never a password value.
        for b in self.assessment["breaches"]:
            self.assertEqual(set(b.keys()), {"name", "passwords_exposed"})

    def test_markdown_renders(self):
        md = OsintAgent().render_markdown(self.assessment)
        self.assertIn("OSINT Risk Assessment — Jordan Rivera", md)
        self.assertIn("73/100", md)
        self.assertIn("High", md)


if __name__ == "__main__":
    unittest.main()

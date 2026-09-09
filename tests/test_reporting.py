import unittest
from pathlib import Path

from vantage.agents.recon import parse_nmap_xml
from vantage.agents.reporting import ReportingAgent, _severity
from vantage.agents.vuln import VulnAnalysisAgent

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


class SeverityTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(_severity(10.0), "Critical")
        self.assertEqual(_severity(7.8), "High")
        self.assertEqual(_severity(5.3), "Medium")
        self.assertEqual(_severity(2.0), "Low")
        self.assertEqual(_severity(0.0), "None")


class ReportTests(unittest.TestCase):
    def setUp(self):
        recon = parse_nmap_xml(FIXTURE.read_text())
        recon["target"] = "192.0.2.10"
        recon["matched_scope"] = "lab"
        self.recon = recon
        self.analysis = VulnAnalysisAgent.with_static_db().analyze(recon)
        self.md = ReportingAgent().render_markdown(recon, self.analysis)

    def test_has_sections(self):
        self.assertIn("# Red Team Findings — 192.0.2.10", self.md)
        self.assertIn("## Executive Summary", self.md)
        self.assertIn("## Open Services", self.md)
        self.assertIn("## Findings (ranked by exploitability)", self.md)

    def test_findings_rendered(self):
        self.assertIn("CVE-2011-2523", self.md)
        self.assertIn("Critical", self.md)
        self.assertIn("no exploitation was performed", self.md)

    def test_empty_findings_message(self):
        empty = {"target": "x", "summary": {}, "findings": []}
        md = ReportingAgent().render_markdown({"hosts": []}, empty)
        self.assertIn("No known CVEs matched", md)


if __name__ == "__main__":
    unittest.main()

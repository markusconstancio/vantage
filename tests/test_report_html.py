import unittest
from pathlib import Path

from vantage.agents.recon import parse_nmap_xml
from vantage.agents.vuln import VulnAnalysisAgent
from vantage.osint.assess import OsintAgent
from vantage.osint.persona import Persona
from vantage.report_html import render_findings_html, render_osint_html

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"
PERSONA = Path(__file__).resolve().parents[1] / "personas" / "jordan-rivera.yaml"


class FindingsHtmlTests(unittest.TestCase):
    def setUp(self):
        recon = parse_nmap_xml(FIXTURE.read_text())
        recon["target"] = "192.0.2.10"
        self.analysis = VulnAnalysisAgent.with_static_db().analyze(recon)
        self.recon = recon
        self.html = render_findings_html(recon, self.analysis)

    def test_valid_shell(self):
        self.assertTrue(self.html.startswith("<!doctype html>"))
        self.assertIn("<title>Red Team Findings", self.html)
        self.assertEqual(self.html.count("<style>"), 1)

    def test_theme_aware(self):
        self.assertIn("prefers-color-scheme:dark", self.html)

    def test_content(self):
        self.assertIn("CVE-2011-2523", self.html)
        self.assertIn("Critical", self.html)
        self.assertIn("192.0.2.10", self.html)

    def test_escapes_untrusted_banner(self):
        # nmap product/version strings are external — must be HTML-escaped.
        recon = {"hosts": [{"address": "192.0.2.10", "state": "up",
                 "hostnames": [], "ports": [
                     {"port": 80, "protocol": "tcp", "state": "open",
                      "service": "http", "product": "<script>alert(1)</script>",
                      "version": "1.0"}]}], "target": "192.0.2.10"}
        analysis = VulnAnalysisAgent.with_static_db().analyze(recon)
        html = render_findings_html(recon, analysis)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


class OsintHtmlTests(unittest.TestCase):
    def setUp(self):
        self.assessment = OsintAgent().assess(Persona.load(PERSONA))
        self.html = render_osint_html(self.assessment)

    def test_valid_shell_and_score(self):
        self.assertTrue(self.html.startswith("<!doctype html>"))
        self.assertIn("<title>OSINT Risk Assessment", self.html)
        self.assertIn(">73<", self.html)
        self.assertIn("High", self.html)

    def test_gauge_and_bars(self):
        self.assertIn('<svg width="180"', self.html)     # radial score gauge
        self.assertIn('<div class="num">73</div>', self.html)
        self.assertIn("Credential stuffing", self.html)
        self.assertIn("rating 3/3", self.html)

    def test_no_breach_passwords_in_html(self):
        self.assertNotIn("password:", self.html.lower())


if __name__ == "__main__":
    unittest.main()

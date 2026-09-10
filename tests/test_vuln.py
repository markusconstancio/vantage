import unittest
from pathlib import Path

from vantage.agents.recon import parse_nmap_xml
from vantage.agents.vuln import StaticCveSource, VulnAnalysisAgent, Vulnerability

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


class StaticSourceTests(unittest.TestCase):
    def setUp(self):
        self.src = StaticCveSource.load()

    def test_vsftpd_backdoor_matched(self):
        vulns = self.src.lookup("vsftpd", "2.3.4")
        self.assertTrue(any(v.cve == "CVE-2011-2523" for v in vulns))

    def test_version_prefix_gate(self):
        # A different vsftpd version must not match the 2.3.4-only entry.
        self.assertEqual(self.src.lookup("vsftpd", "3.0.3"), [])

    def test_samba_substring_product_match(self):
        # nmap product is "Samba smbd"; entry product is "Samba".
        vulns = self.src.lookup("Samba smbd", "3.0.20-Debian")
        self.assertTrue(any(v.cve == "CVE-2007-2447" for v in vulns))

    def test_unknown_product(self):
        self.assertEqual(self.src.lookup("nginx", "1.25.0"), [])

    def test_empty_product(self):
        self.assertEqual(self.src.lookup("", "1.0"), [])


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        recon = parse_nmap_xml(FIXTURE.read_text())
        recon["target"] = "192.0.2.10"
        self.analysis = VulnAnalysisAgent.with_static_db().analyze(recon)

    def test_findings_present(self):
        cves = {f["cve"] for f in self.analysis["findings"]}
        self.assertIn("CVE-2011-2523", cves)  # vsftpd
        self.assertIn("CVE-2007-2447", cves)  # samba
        self.assertIn("CVE-2011-3192", cves)  # apache
        self.assertIn("CVE-2018-15473", cves)  # openssh

    def test_ranked_by_exploitability_then_cvss(self):
        findings = self.analysis["findings"]
        # vsftpd backdoor (CVSS 10, exploit) must rank first.
        self.assertEqual(findings[0]["cve"], "CVE-2011-2523")
        cvsss = [f["cvss"] for f in findings if f["exploit_available"]]
        self.assertEqual(cvsss, sorted(cvsss, reverse=True))

    def test_summary_counts(self):
        s = self.analysis["summary"]
        self.assertEqual(s["findings"], len(self.analysis["findings"]))
        self.assertEqual(s["max_cvss"], 10.0)
        self.assertGreaterEqual(s["open_services"], 6)

    def test_finding_carries_port_context(self):
        vsftpd = next(f for f in self.analysis["findings"]
                      if f["cve"] == "CVE-2011-2523")
        self.assertEqual(vsftpd["port"], 21)
        self.assertEqual(vsftpd["host"], "192.0.2.10")

    def test_custom_source_via_protocol(self):
        class FakeSource:
            def lookup(self, product, version):
                return [Vulnerability("CVE-0000-1", "t", 5.0, False)]
        recon = {"hosts": [{"address": "x", "ports": [
            {"port": 80, "protocol": "tcp", "state": "open",
             "product": "anything", "version": "1"}]}]}
        out = VulnAnalysisAgent(source=FakeSource()).analyze(recon)
        self.assertEqual(len(out["findings"]), 1)


if __name__ == "__main__":
    unittest.main()

import unittest
from pathlib import Path

from vantage.agents.recon import ReconAgent, parse_nmap_xml
from vantage.audit import AuditLog
from vantage.scope import OutOfScopeError, Scope

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def in_scope():
    return Scope.from_dict(
        {"red_team": {"targets": [
            {"name": "lab", "address": "192.0.2.10", "type": "host",
             "authorized": True},
        ]}}
    )


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.result = parse_nmap_xml(FIXTURE.read_text())

    def test_single_host_parsed(self):
        self.assertEqual(len(self.result["hosts"]), 1)
        host = self.result["hosts"][0]
        self.assertEqual(host["address"], "192.0.2.10")
        self.assertEqual(host["state"], "up")
        self.assertIn("metasploitable.localdomain", host["hostnames"])

    def test_services_and_versions(self):
        ports = {p["port"]: p for p in self.result["hosts"][0]["ports"]}
        self.assertEqual(ports[21]["service"], "ftp")
        self.assertEqual(ports[21]["product"], "vsftpd")
        self.assertEqual(ports[21]["version"], "2.3.4")
        self.assertEqual(ports[80]["product"], "Apache httpd")
        self.assertEqual(ports[3306]["service"], "mysql")
        self.assertTrue(all(p["state"] == "open" for p in ports.values()))

    def test_empty_xml_raises(self):
        from vantage.agents.recon import ReconError
        with self.assertRaises(ReconError):
            parse_nmap_xml("")


class ScanGateTests(unittest.TestCase):
    def setUp(self):
        # Isolate the audit log to a temp path so tests don't touch logs/.
        self.tmp_log = Path(self.id().replace(".", "_") + ".audit.log")
        self.audit = AuditLog(self.tmp_log)

    def tearDown(self):
        if self.tmp_log.exists():
            self.tmp_log.unlink()

    def test_out_of_scope_refused_before_running(self):
        agent = ReconAgent(scope=in_scope(), audit=self.audit)
        with self.assertRaises(OutOfScopeError):
            agent.scan("192.0.2.99")

    def test_dry_run_builds_command_for_in_scope(self):
        agent = ReconAgent(scope=in_scope(), audit=self.audit)
        result = agent.scan("192.0.2.10", dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["matched_scope"], "lab")
        cmd = result["command"]
        self.assertIn("-sV", cmd)
        self.assertIn("192.0.2.10", cmd)
        self.assertEqual(cmd[-1], "192.0.2.10")

    def test_dry_run_is_audited(self):
        agent = ReconAgent(scope=in_scope(), audit=self.audit)
        agent.scan("192.0.2.10", dry_run=True)
        contents = self.tmp_log.read_text()
        self.assertIn("recon.scan", contents)
        self.assertIn("192.0.2.10", contents)

    def test_ports_flag_in_command(self):
        agent = ReconAgent(scope=in_scope(), audit=self.audit)
        result = agent.scan("192.0.2.10", ports="1-1000", dry_run=True)
        cmd = result["command"]
        self.assertIn("-p", cmd)
        self.assertIn("1-1000", cmd)


if __name__ == "__main__":
    unittest.main()

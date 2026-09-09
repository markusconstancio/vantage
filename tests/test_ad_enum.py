import unittest
from pathlib import Path

from vantage.agents.ad_enum import ADEnumAgent, parse_ad_xml
from vantage.agents.recon import ReconError
from vantage.audit import AuditLog
from vantage.scope import OutOfScopeError, Scope

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_ad_sample.xml"


def in_scope():
    return Scope.from_dict({"red_team": {"targets": [
        {"name": "dc", "address": "192.0.2.20", "type": "host",
         "authorized": True},
    ]}})


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.result = parse_ad_xml(FIXTURE.read_text())
        self.host = self.result["hosts"][0]

    def test_address_and_os(self):
        self.assertEqual(self.host["address"], "192.0.2.20")
        self.assertIn("Windows Server 2019", self.host["os_discovery"])
        self.assertIn("Domain: LAB", self.host["os_discovery"])

    def test_shares(self):
        self.assertIn("SYSVOL", self.host["shares"])
        self.assertIn("backups", self.host["shares"])

    def test_users(self):
        self.assertIn("LAB\\Administrator", self.host["users"])
        self.assertIn("LAB\\svc_backup", self.host["users"])

    def test_security_mode(self):
        self.assertIn("message_signing", self.host["security_mode"])

    def test_empty_raises(self):
        with self.assertRaises(ReconError):
            parse_ad_xml("")


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp_log = Path(self.id().replace(".", "_") + ".audit.log")
        self.audit = AuditLog(self.tmp_log)

    def tearDown(self):
        if self.tmp_log.exists():
            self.tmp_log.unlink()

    def test_out_of_scope_refused(self):
        agent = ADEnumAgent(scope=in_scope(), audit=self.audit)
        with self.assertRaises(OutOfScopeError):
            agent.enumerate("192.0.2.99")

    def test_dry_run_command(self):
        agent = ADEnumAgent(scope=in_scope(), audit=self.audit)
        result = agent.enumerate("192.0.2.20", dry_run=True)
        self.assertTrue(result["dry_run"])
        cmd = result["command"]
        self.assertIn("--script", cmd)
        self.assertIn("smb-enum-shares", " ".join(cmd))
        self.assertEqual(cmd[-1], "192.0.2.20")

    def test_scripts_are_enumeration_only(self):
        # Guard against anyone slipping a brute/exploit script into defaults.
        agent = ADEnumAgent(scope=in_scope(), audit=self.audit)
        joined = " ".join(agent.scripts)
        for banned in ("brute", "exploit", "vuln", "dos"):
            self.assertNotIn(banned, joined)


if __name__ == "__main__":
    unittest.main()

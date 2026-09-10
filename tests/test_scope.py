import unittest

from vantage.scope import OutOfScopeError, Scope, ScopeConfigError


def make_scope(targets):
    return Scope.from_dict({"red_team": {"targets": targets}})


HOST = {
    "name": "lab-host",
    "address": "192.0.2.10",
    "type": "host",
    "authorized": True,
}
NET = {
    "name": "lab-net",
    "address": "192.0.2.0/24",
    "type": "network",
    "authorized": True,
}


class ScopeGateTests(unittest.TestCase):
    def test_exact_ip_authorized(self):
        s = make_scope([HOST])
        self.assertTrue(s.is_authorized("192.0.2.10"))
        self.assertEqual(s.require_authorized("192.0.2.10").name, "lab-host")

    def test_out_of_scope_ip_refused(self):
        s = make_scope([HOST])
        self.assertFalse(s.is_authorized("192.0.2.99"))
        with self.assertRaises(OutOfScopeError):
            s.require_authorized("192.0.2.99")

    def test_cidr_membership(self):
        s = make_scope([NET])
        self.assertTrue(s.is_authorized("192.0.2.55"))
        self.assertFalse(s.is_authorized("192.0.3.55"))

    def test_empty_scope_refuses_everything(self):
        s = make_scope([])
        self.assertFalse(s.is_authorized("192.0.2.10"))
        with self.assertRaises(OutOfScopeError):
            s.require_authorized("192.0.2.10")

    def test_unauthorized_flag_refused(self):
        entry = dict(HOST, authorized=False)
        s = make_scope([entry])
        self.assertFalse(s.is_authorized("192.0.2.10"))
        with self.assertRaises(OutOfScopeError):
            s.require_authorized("192.0.2.10")

    def test_hostname_literal_match(self):
        entry = {"name": "box", "address": "meta.lab", "type": "host",
                 "authorized": True}
        s = make_scope([entry])
        self.assertTrue(s.is_authorized("meta.lab"))
        self.assertTrue(s.is_authorized("META.LAB"))
        self.assertFalse(s.is_authorized("other.lab"))
        # A hostname entry must not authorize an arbitrary IP.
        self.assertFalse(s.is_authorized("192.0.2.10"))

    def test_invalid_cidr_rejected(self):
        with self.assertRaises(ScopeConfigError):
            make_scope([{"name": "bad", "address": "nope", "type": "network",
                         "authorized": True}])

    def test_missing_address_rejected(self):
        with self.assertRaises(ScopeConfigError):
            make_scope([{"name": "bad", "type": "host", "authorized": True}])


class ShippedScopeFileTests(unittest.TestCase):
    def test_repo_scope_yaml_has_no_real_targets(self):
        # The committed scope.yaml must ship empty of real targets.
        s = Scope.load()
        self.assertEqual(s.targets, [])


if __name__ == "__main__":
    unittest.main()

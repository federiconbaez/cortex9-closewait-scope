import unittest

from closewait_scope.model import age_histogram, classify, compare
from closewait_scope.owners import peer_class


def g(**kw):
    d = {"role": "server", "seen": 10, "left": 0, "rxq_nonzero_frac": 0.0, "leak_rate_per_s": 1.0}
    d.update(kw)
    return d


class Peer(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(peer_class("127.0.0.1"), "loopback")
        self.assertEqual(peer_class("::1"), "loopback")
        self.assertEqual(peer_class("10.20.0.1"), "private")
        self.assertEqual(peer_class("172.31.255.1"), "private")
        self.assertEqual(peer_class("100.64.1.1"), "private")
        self.assertEqual(peer_class("fd00::5"), "private")
        self.assertEqual(peer_class("8.8.8.8"), "public")
        self.assertEqual(peer_class("203.0.113.7"), "public")
        self.assertEqual(peer_class("2001:db8::7"), "public")
        self.assertEqual(peer_class("172.32.0.1"), "public")


class Classify(unittest.TestCase):
    def test_client_is_pool(self):
        self.assertEqual(classify(g(role="client")), "upstream_keepalive_pool")

    def test_unread_is_backlog(self):
        self.assertEqual(classify(g(rxq_nonzero_frac=0.5, left=8)), "worker_backlog_timeout")

    def test_never_closes(self):
        self.assertEqual(classify(g()), "app_never_closes")

    def test_server_with_churn_unknown(self):
        self.assertEqual(classify(g(left=5)), "unknown")

    def test_unknown_owner(self):
        self.assertEqual(classify(g(role="unknown_owner")), "unknown")

    def test_draining_server_not_leak(self):
        self.assertEqual(classify(g(leak_rate_per_s=-0.5)), "unknown")


class Hist(unittest.TestCase):
    def test_buckets(self):
        h = age_histogram([0.1, 2, 4.9, 31, 7200])
        self.assertEqual(h["<1s"], 1)
        self.assertEqual(h["<5s"], 2)
        self.assertEqual(h["<120s"], 1)
        self.assertEqual(h[">=3600s"], 1)
        self.assertEqual(sum(h.values()), 5)


class Compare(unittest.TestCase):
    def rep(self, cur, rate):
        return [{"comm": "nginx", "role": "client", "port": 8000, "peer_class": "loopback",
                 "current": cur, "leak_rate_per_s": rate}]

    def test_improved(self):
        self.assertEqual(compare(self.rep(100, 2.0), self.rep(3, 0.0))["overall"], "mejoro")

    def test_worse(self):
        self.assertEqual(compare(self.rep(10, 0.0), self.rep(40, 1.0))["overall"], "empeoro")

    def test_same(self):
        self.assertEqual(compare(self.rep(10, 0.0), self.rep(10, 0.0))["overall"], "igual")

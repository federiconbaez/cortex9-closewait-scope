"""Sockets reales en loopback: crea CLOSE_WAIT de lado servidor y cliente en este proceso."""
import os
import socket
import time
import unittest

from closewait_scope.model import Tracker, take_snapshot


def pair():
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(16)
    c = socket.create_connection(ls.getsockname())
    s, _ = ls.accept()
    return ls, c, s


def wait_cw(pred, backend):
    for _ in range(50):
        snap = take_snapshot(backend, {os.getpid()})
        hits = [e for e in snap.entries if pred(e)]
        if hits:
            return snap, hits
        time.sleep(0.02)
    raise AssertionError("no apareció el CLOSE_WAIT esperado")


class Live(unittest.TestCase):
    def check_backend(self, backend):
        ls, c, s = pair()
        port = ls.getsockname()[1]
        try:
            c.sendall(b"GET / HTTP/1.1\r\n\r\n")
            c.close()   # el servidor queda en CLOSE_WAIT con 18 bytes sin leer
            snap, hits = wait_cw(lambda e: e.sock.lport == port, backend)
            self.assertEqual(snap.backend, backend)
            e = hits[0]
            self.assertEqual(e.pids, (os.getpid(),))
            self.assertEqual(e.role, "server")
            self.assertEqual(e.peer, "loopback")
            # 18 bytes de payload + 1 por el FIN que la app todavía no leyó
            self.assertEqual(e.sock.rx_queue, 19)
        finally:
            s.close()
            ls.close()

    def test_netlink(self):
        self.check_backend("netlink")

    def test_proc(self):
        self.check_backend("proc")

    def test_client_side(self):
        ls, c, s = pair()
        port = ls.getsockname()[1]
        try:
            s.close()   # el cliente queda en CLOSE_WAIT
            _, hits = wait_cw(lambda e: e.sock.rport == port, "auto")
            self.assertEqual(hits[0].role, "client")
            self.assertEqual(hits[0].sock.rx_queue, 1)  # solo el FIN sin leer
        finally:
            c.close()
            ls.close()

    def test_tracker_age_and_leave(self):
        ls, c, s = pair()
        port = ls.getsockname()[1]
        tr = Tracker()
        try:
            c.close()
            wait_cw(lambda e: e.sock.lport == port, "auto")
            tr.add(take_snapshot("auto", {os.getpid()}))
            time.sleep(0.3)
            tr.add(take_snapshot("auto", {os.getpid()}))
            rep = [d for d in tr.report() if d["port"] == port][0]
            self.assertEqual(rep["current"], 1)
            self.assertEqual(rep["censored_at_start"], 1)
            self.assertEqual(rep["cause"], "app_never_closes")
            s.close()
            tr.add(take_snapshot("auto", {os.getpid()}))
            rep = [d for d in tr.report() if d["port"] == port][0]
            self.assertEqual((rep["current"], rep["left"]), (0, 1))
        finally:
            ls.close()

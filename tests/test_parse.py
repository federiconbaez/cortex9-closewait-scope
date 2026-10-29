import socket
import struct
import unittest

from closewait_scope.diag import parse_diag_msg, parse_proc_net_tcp, _build_req

TCP4 = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:D431 08 00000000:00000010 00:00000000 00000000  1000        0 424242 1 0000000000000000 20 4 30 10 -1
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000000000000000 100 0 0 10 0
"""
TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0050 0000000000000000FFFF00000100007F:9C40 08 00000000:00000000 00:00000000 00000000     0        0 777 1 0000000000000000 20 4 0 10 -1
   1: 000080FE00000000FF005450B6AD1DFE:0050 00000000000000000000000001000000:9C41 08 00000005:00000000 00:00000000 00000000     0        0 778 1 0000000000000000 20 4 0 10 -1
"""


class ParseProc(unittest.TestCase):
    def test_ipv4_close_wait(self):
        s = parse_proc_net_tcp(TCP4, socket.AF_INET)
        self.assertEqual(len(s), 2)
        cw = s[0]
        self.assertEqual((cw.laddr, cw.lport, cw.raddr, cw.rport), ("127.0.0.1", 8080, "127.0.0.1", 54321))
        self.assertEqual((cw.state, cw.rx_queue, cw.tx_queue, cw.uid, cw.inode), (8, 16, 0, 1000, 424242))
        self.assertEqual(s[1].state, 10)

    def test_ipv6_and_mapped(self):
        s = parse_proc_net_tcp(TCP6, socket.AF_INET6)
        self.assertEqual(s[0].laddr, "::1")
        self.assertEqual(s[0].raddr, "127.0.0.1")  # ::ffff:127.0.0.1 normalizada
        self.assertEqual(s[0].rport, 40000)
        self.assertEqual(s[1].laddr, "fe80::5054:ff:fe1d:adb6")
        self.assertEqual(s[1].tx_queue, 5)


class ParseNetlink(unittest.TestCase):
    def test_diag_msg_ipv4(self):
        payload = struct.pack("=BBBB", socket.AF_INET, 8, 0, 0)
        payload += struct.pack("!HH", 8080, 54321)
        payload += socket.inet_aton("10.1.2.3") + b"\0" * 12
        payload += socket.inet_aton("203.0.113.9") + b"\0" * 12
        payload += struct.pack("=I", 0) + b"\0" * 8          # if + cookie
        payload += struct.pack("=IIIII", 0, 7, 0, 1000, 99)   # expires rq wq uid inode
        s = parse_diag_msg(payload)
        self.assertEqual((s.laddr, s.lport, s.raddr, s.rport), ("10.1.2.3", 8080, "203.0.113.9", 54321))
        self.assertEqual((s.state, s.rx_queue, s.uid, s.inode), (8, 7, 1000, 99))

    def test_request_layout(self):
        r = _build_req(socket.AF_INET, 1 << 8, 1)
        ln, typ, flags, seq, _ = struct.unpack_from("=IHHII", r, 0)
        self.assertEqual((ln, typ, seq), (16 + 56, 20, 1))
        self.assertEqual(flags, 0x301)
        fam, proto, _e, _p, states = struct.unpack_from("=BBBBI", r, 16)
        self.assertEqual((fam, proto, states), (socket.AF_INET, 6, 256))

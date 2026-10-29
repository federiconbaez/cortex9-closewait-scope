"""Lectura de sockets TCP: netlink sock_diag (filtrado en kernel) y /proc/net/tcp{,6}.

Ninguna de las dos rutas necesita root para listar sockets; atribuir un socket a un
proceso sí exige poder leer /proc/<pid>/fd de ese proceso (ver owners.py).
"""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass, asdict

TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2",
    6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING",
}
CLOSE_WAIT = 8
LISTEN = 10

NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLM_F_REQUEST = 0x1
NLM_F_DUMP = 0x300
NLMSG_ERROR = 2
NLMSG_DONE = 3


@dataclass(frozen=True)
class Sock:
    family: int          # socket.AF_INET o AF_INET6
    state: int
    laddr: str
    lport: int
    raddr: str
    rport: int
    rx_queue: int
    tx_queue: int
    uid: int
    inode: int

    def key(self) -> tuple:
        return (self.laddr, self.lport, self.raddr, self.rport)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["state"] = TCP_STATES.get(self.state, str(self.state))
        return d


# ---------------------------------------------------------------- /proc/net/tcp

def _hex_ipv4(h: str) -> str:
    return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(h, 16)))


def _hex_ipv6(h: str) -> str:
    words = [int(h[i:i + 8], 16) for i in range(0, 32, 8)]
    return socket.inet_ntop(socket.AF_INET6, struct.pack("<4I", *words))


def _norm(addr: str) -> str:
    """Normaliza IPv4 mapeada en IPv6 (::ffff:a.b.c.d) a a.b.c.d."""
    if addr.startswith("::ffff:") and "." in addr:
        return addr[7:]
    return addr


def parse_proc_net_tcp(text: str, family: int) -> list[Sock]:
    out: list[Sock] = []
    conv = _hex_ipv4 if family == socket.AF_INET else _hex_ipv6
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        la, lp = f[1].split(":")
        ra, rp = f[2].split(":")
        txq, rxq = f[4].split(":")
        out.append(Sock(family, int(f[3], 16), _norm(conv(la)), int(lp, 16),
                        _norm(conv(ra)), int(rp, 16), int(rxq, 16), int(txq, 16),
                        int(f[7]), int(f[9])))
    return out


def read_proc(states: set[int] | None = None, proc_root: str = "/proc") -> list[Sock]:
    socks: list[Sock] = []
    for name, fam in (("tcp", socket.AF_INET), ("tcp6", socket.AF_INET6)):
        p = os.path.join(proc_root, "net", name)
        try:
            with open(p) as fh:
                socks += parse_proc_net_tcp(fh.read(), fam)
        except FileNotFoundError:
            continue
    if states is not None:
        socks = [s for s in socks if s.state in states]
    return socks


# ---------------------------------------------------------------- netlink sock_diag

def _build_req(family: int, states_mask: int, seq: int) -> bytes:
    req = struct.pack("=BBBBI", family, socket.IPPROTO_TCP, 0, 0, states_mask)
    req += b"\x00" * 48  # inet_diag_sockid vacío: dump completo filtrado por estado
    hdr = struct.pack("=IHHII", 16 + len(req), SOCK_DIAG_BY_FAMILY,
                      NLM_F_REQUEST | NLM_F_DUMP, seq, 0)
    return hdr + req


def parse_diag_msg(payload: bytes) -> Sock:
    family, state, _timer, _retrans = struct.unpack_from("=BBBB", payload, 0)
    sport, dport = struct.unpack_from("!HH", payload, 4)
    src = payload[8:24]
    dst = payload[24:40]
    _expires, rq, wq, uid, inode = struct.unpack_from("=IIIII", payload, 52)
    if family == socket.AF_INET:
        la = socket.inet_ntop(socket.AF_INET, src[:4])
        ra = socket.inet_ntop(socket.AF_INET, dst[:4])
    else:
        la = _norm(socket.inet_ntop(socket.AF_INET6, src))
        ra = _norm(socket.inet_ntop(socket.AF_INET6, dst))
    return Sock(family, state, la, sport, ra, dport, rq, wq, uid, inode)


def read_netlink(states: set[int]) -> list[Sock]:
    mask = 0
    for s in states:
        mask |= 1 << s
    out: list[Sock] = []
    with socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_SOCK_DIAG) as nl:
        for seq, fam in enumerate((socket.AF_INET, socket.AF_INET6), start=1):
            nl.send(_build_req(fam, mask, seq))
            done = False
            while not done:
                data = nl.recv(1 << 16)
                off = 0
                while off + 16 <= len(data):
                    ln, typ, _fl, _sq, _pid = struct.unpack_from("=IHHII", data, off)
                    if ln < 16:
                        raise OSError("netlink: mensaje truncado")
                    if typ == NLMSG_DONE:
                        done = True
                        break
                    if typ == NLMSG_ERROR:
                        (err,) = struct.unpack_from("=i", data, off + 16)
                        if err == 0:
                            off += (ln + 3) & ~3
                            continue
                        raise OSError(-err, "sock_diag: " + os.strerror(-err))
                    if typ == SOCK_DIAG_BY_FAMILY:
                        out.append(parse_diag_msg(data[off + 16: off + ln]))
                    off += (ln + 3) & ~3
    return [s for s in out if s.state in states]


def read_sockets(states: set[int], backend: str = "auto") -> tuple[list[Sock], str]:
    """Devuelve (sockets, backend_usado). 'auto' intenta netlink y cae a /proc."""
    if backend in ("auto", "netlink"):
        try:
            return read_netlink(states), "netlink"
        except OSError:
            if backend == "netlink":
                raise
    return read_proc(states), "proc"

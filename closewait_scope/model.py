"""Snapshots, seguimiento de edad, tasa de fuga y huellas de causa."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .diag import CLOSE_WAIT, LISTEN, Sock, read_sockets
from .owners import inode_owners, peer_class

CAUSES = {
    "upstream_keepalive_pool": (
        "CLOSE_WAIT del lado cliente hacia un upstream: conexiones keepalive en un pool "
        "que el upstream ya cerró por inactividad y el cliente no lee hasta reusarlas "
        "(pool de nginx upstream keepalive, urllib3/requests, clientes HTTP con pool).",
        "Bajar el idle timeout del pool por debajo del keepalive_timeout del upstream, "
        "o habilitar chequeo de conexión vieja antes de reusar."),
    "worker_backlog_timeout": (
        "CLOSE_WAIT del lado servidor con bytes de request sin leer: el peer se rindió "
        "mientras la conexión esperaba un worker libre (gunicorn gthread saturado, "
        "pool de threads chico frente a handlers lentos).",
        "Más threads/workers, timeout del proxy mayor que el tiempo en cola, o "
        "limitar la cola de aceptación."),
    "app_never_closes": (
        "CLOSE_WAIT del lado servidor con el request ya leído y sin salida: la "
        "aplicación nunca llama close() (fuga de fd en el código).",
        "Buscar el camino de código que no cierra (try/finally, context manager); "
        "la cuenta crece hasta agotar fds."),
    "unknown": ("Sin huella conocida con los datos observados.", "Observar más tiempo."),
}


@dataclass
class Entry:
    sock: Sock
    pids: tuple[int, ...]
    comm: str
    role: str          # server | client | unknown_owner
    peer: str          # loopback | private | public


@dataclass
class Snapshot:
    t: float
    backend: str
    entries: list[Entry]
    listen_ports: dict[int, set[int]]   # pid -> puertos en LISTEN
    denied: int


def take_snapshot(backend: str = "auto", only_pids: set[int] | None = None) -> Snapshot:
    t = time.monotonic()
    socks, used = read_sockets({CLOSE_WAIT, LISTEN}, backend)
    cw = [s for s in socks if s.state == CLOSE_WAIT]
    listens = [s for s in socks if s.state == LISTEN]
    owners: dict = {}
    denied = 0
    if cw:
        owners, denied = inode_owners(only_pids=only_pids)
    listen_ports: dict[int, set[int]] = {}
    for s in listens:
        for p in owners.get(s.inode, []):
            listen_ports.setdefault(p.pid, set()).add(s.lport)
    entries = []
    for s in cw:
        procs = owners.get(s.inode, [])
        if only_pids is not None and not procs:
            continue
        pids = tuple(sorted({p.pid for p in procs}))
        comm = procs[0].comm if procs else "?"
        if not pids:
            role = "unknown_owner"
        elif any(s.lport in listen_ports.get(pid, ()) for pid in pids):
            role = "server"
        else:
            role = "client"
        entries.append(Entry(s, pids, comm, role, peer_class(s.raddr)))
    return Snapshot(t, used, entries, listen_ports, denied)


def group_key(e: Entry) -> tuple:
    port = e.sock.lport if e.role == "server" else e.sock.rport
    return (e.pids[0] if e.pids else 0, e.comm, e.role, port, e.peer)


@dataclass
class GroupStats:
    key: tuple
    counts: list[int] = field(default_factory=list)
    seen: set = field(default_factory=set)        # inodes observados en la ventana
    left: set = field(default_factory=set)        # inodes que salieron de CLOSE_WAIT
    rxq_nonzero: set = field(default_factory=set)
    first_seen: dict = field(default_factory=dict)
    censored: set = field(default_factory=set)    # ya estaban en el primer snapshot

    def as_dict(self, now: float, t0: float, t1: float) -> dict:
        pid, comm, role, port, peer = self.key
        alive = [i for i in self.first_seen if i not in self.left]
        ages = sorted(now - self.first_seen[i] for i in alive)
        span = max(t1 - t0, 1e-9)
        return {
            "pid": pid, "comm": comm, "role": role,
            "port": port, "port_kind": "local" if role == "server" else "remote",
            "peer_class": peer, "current": self.counts[-1] if self.counts else 0,
            "seen": len(self.seen), "left": len(self.left),
            "rxq_nonzero_frac": round(len(self.rxq_nonzero) / max(len(self.seen), 1), 3),
            "leak_rate_per_s": round(((self.counts[-1] - self.counts[0]) if self.counts else 0) / span, 3),
            "age_hist_s": age_histogram(ages),
            "age_is_lower_bound": True,
            "censored_at_start": len(self.censored),
        }


AGE_BUCKETS = (1, 5, 30, 120, 600, 3600)


def age_histogram(ages: list[float]) -> dict:
    h = {f"<{b}s": 0 for b in AGE_BUCKETS}
    h[f">={AGE_BUCKETS[-1]}s"] = 0
    for a in ages:
        for b in AGE_BUCKETS:
            if a < b:
                h[f"<{b}s"] += 1
                break
        else:
            h[f">={AGE_BUCKETS[-1]}s"] += 1
    return h


class Tracker:
    """Acumula snapshots. La edad es una cota inferior con resolución = intervalo."""

    def __init__(self) -> None:
        self.groups: dict[tuple, GroupStats] = {}
        self.t0: float | None = None
        self.t1: float | None = None
        self.n = 0

    def add(self, snap: Snapshot) -> None:
        first = self.n == 0
        self.n += 1
        if self.t0 is None:
            self.t0 = snap.t
        self.t1 = snap.t
        current: dict[tuple, set] = {}
        for e in snap.entries:
            k = group_key(e)
            g = self.groups.setdefault(k, GroupStats(k))
            ino = e.sock.inode
            current.setdefault(k, set()).add(ino)
            if ino not in g.first_seen:
                g.first_seen[ino] = snap.t
                if first:
                    g.censored.add(ino)
            g.seen.add(ino)
            # En CLOSE_WAIT el kernel cuenta el FIN como 1 byte de rx_queue mientras la
            # app no leyó el EOF; >1 significa bytes de payload sin leer.
            if e.sock.rx_queue > 1:
                g.rxq_nonzero.add(ino)
        for k, g in self.groups.items():
            now_set = current.get(k, set())
            for ino in list(g.first_seen):
                if ino not in now_set and ino not in g.left:
                    g.left.add(ino)
            g.counts.append(len(now_set))

    def report(self) -> list[dict]:
        out = []
        for g in self.groups.values():
            d = g.as_dict(self.t1, self.t0, self.t1)
            cause = classify(d)
            d["cause"] = cause
            d["explanation"], d["suggestion"] = CAUSES[cause]
            out.append(d)
        out.sort(key=lambda d: -d["current"])
        return out


def classify(d: dict) -> str:
    """Huellas de causa. Reglas fijas (pre-registradas en lab/PREREGISTRO.md).

    - client                                 -> upstream_keepalive_pool
    - server y >=50% con payload sin leer (rx_queue > 1; el FIN cuenta 1)      -> worker_backlog_timeout
    - server, <50% sin leer, sin salidas (<5% de los vistos) y cuenta que no baja
                                             -> app_never_closes
    - resto                                  -> unknown
    """
    if d["role"] == "client":
        return "upstream_keepalive_pool"
    if d["role"] != "server" or d["seen"] == 0:
        return "unknown"
    if d["rxq_nonzero_frac"] >= 0.5:
        return "worker_backlog_timeout"
    if d["left"] / d["seen"] < 0.05 and d["leak_rate_per_s"] >= 0:
        return "app_never_closes"
    return "unknown"


def compare(before: list[dict], after: list[dict], tol: float = 0.2) -> dict:
    """Veredicto antes/después por grupo (comm, rol, puerto, peer)."""
    def idx(rep):
        return {(d["comm"], d["role"], d["port"], d["peer_class"]): d for d in rep}
    b, a = idx(before), idx(after)
    rows = []
    for k in sorted(set(b) | set(a), key=str):
        cb = b.get(k, {}).get("current", 0)
        ca = a.get(k, {}).get("current", 0)
        rb = b.get(k, {}).get("leak_rate_per_s", 0.0)
        ra = a.get(k, {}).get("leak_rate_per_s", 0.0)
        if ca <= cb * (1 - tol) and ra <= rb:
            v = "mejoro"
        elif ca >= max(cb * (1 + tol), cb + 1) or ra > rb + 1e-9:
            v = "empeoro"
        else:
            v = "igual"
        rows.append({"group": list(k), "before": cb, "after": ca,
                     "rate_before": rb, "rate_after": ra, "verdict": v})
    overall = "mejoro" if rows and all(r["verdict"] != "empeoro" for r in rows) and any(
        r["verdict"] == "mejoro" for r in rows) else (
        "empeoro" if any(r["verdict"] == "empeoro" for r in rows) else "igual")
    return {"overall": overall, "groups": rows}

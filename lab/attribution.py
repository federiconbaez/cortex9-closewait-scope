"""Experimento B del pre-registro: atribución de 1.000 CLOSE_WAIT (semilla 49).

Se re-ejecuta a sí mismo dentro de `unshare -rn` (namespace de red sin privilegios).
"""
from __future__ import annotations

import json
import os
import random
import signal
import socket
import subprocess
import sys
import time

ADDRS = {
    "loopback": [("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)],
    "private": [("10.49.0.1", socket.AF_INET), ("fd00::49", socket.AF_INET6)],
    "public": [("203.0.113.49", socket.AF_INET), ("2001:db8::49", socket.AF_INET6)],
}
CLASS_OF = {a: c for c, lst in ADDRS.items() for a, _ in lst}
N_SOCK = 1000
N_DECOY = 100
N_SERVERS = 5
SEED = 49


def setup_netns() -> None:
    cmds = [["ip", "link", "set", "lo", "up"],
            ["ip", "addr", "add", "10.49.0.1/32", "dev", "lo"],
            ["ip", "addr", "add", "203.0.113.49/32", "dev", "lo"],
            ["ip", "-6", "addr", "add", "fd00::49/128", "dev", "lo", "nodad"],
            ["ip", "-6", "addr", "add", "2001:db8::49/128", "dev", "lo", "nodad"]]
    for c in cmds:
        subprocess.run(c, check=True)


def server(idx: int, port: int, r_fd: int, w_fd: int, fork_child: bool) -> None:
    """Acepta y guarda sockets sin cerrarlos; al recibir 'dump' escribe la verdad de terreno."""
    ls = socket.socket(socket.AF_INET6)
    ls.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    ls.bind(("::", port))
    ls.listen(4096)
    ls.settimeout(0.05)
    held = []
    rf = os.fdopen(r_fd, "r")
    wf = os.fdopen(w_fd, "w")
    os.set_blocking(r_fd, False)
    child = None
    while True:
        try:
            c, addr = ls.accept()
            ra = addr[0][7:] if addr[0].startswith("::ffff:") else addr[0]
            held.append((c, ra, addr[1]))
        except socket.timeout:
            pass
        try:
            line = rf.readline()
        except (BlockingIOError, TypeError):
            line = ""
        if line.strip() == "fork" and fork_child:
            child = os.fork()
            if child == 0:
                signal.pause()
                os._exit(0)
            wf.write(json.dumps({"child": child}) + "\n")
            wf.flush()
        elif line.strip() == "dump":
            pids = [os.getpid()] + ([child] if child else [])
            wf.write(json.dumps({"pids": pids, "socks": [[ra, rp] for _, ra, rp in held]}) + "\n")
            wf.flush()
        elif line.strip() == "quit":
            if child:
                os.kill(child, signal.SIGKILL)
            os._exit(0)


def inner() -> dict:
    setup_netns()
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from closewait_scope.model import take_snapshot

    rng = random.Random(SEED)
    servers = []
    for i in range(N_SERVERS):
        port = 20000 + i
        r1, w1 = os.pipe()   # padre -> servidor
        r2, w2 = os.pipe()   # servidor -> padre
        pid = os.fork()
        if pid == 0:
            os.close(w1)
            os.close(r2)
            server(i, port, r1, w2, fork_child=(i == N_SERVERS - 1))
            os._exit(0)
        os.close(r1)
        os.close(w2)
        servers.append({"pid": pid, "port": port, "w": os.fdopen(w1, "w"), "r": os.fdopen(r2, "r")})
    time.sleep(0.5)
    flat = [(a, f) for lst in ADDRS.values() for a, f in lst]
    for _ in range(N_SOCK):
        srv = rng.choice(servers)
        src, fam = rng.choice(flat)
        dst = "::1" if fam == socket.AF_INET6 and src == "::1" else ("127.0.0.1" if fam == socket.AF_INET and src == "127.0.0.1" else src)
        c = socket.socket(fam)
        c.bind((src, 0))
        c.connect((dst, srv["port"]))
        c.close()
    decoys = []
    for _ in range(N_DECOY):
        srv = rng.choice(servers)
        c = socket.create_connection(("127.0.0.1", srv["port"]))
        decoys.append(c)
    time.sleep(1.0)
    last = servers[-1]
    last["w"].write("fork\n")
    last["w"].flush()
    child = json.loads(last["r"].readline())["child"]
    time.sleep(0.3)
    truth = {}
    for s in servers:
        s["w"].write("dump\n")
        s["w"].flush()
        d = json.loads(s["r"].readline())
        for ra, rp in d["socks"]:
            truth[(ra, rp, s["port"])] = (tuple(sorted(d["pids"])), CLASS_OF[ra], ra)
    decoy_keys = {(c.getsockname()[0], c.getsockname()[1]) for c in decoys}
    # los señuelos están ESTABLISHED: no son parte de la verdad de terreno de CLOSE_WAIT
    truth = {k: v for k, v in truth.items() if (k[0], k[1]) not in decoy_keys}

    t0 = time.perf_counter()
    snap = take_snapshot("auto")
    scan_s = time.perf_counter() - t0
    seen = {}
    for e in snap.entries:
        seen[(e.sock.raddr, e.sock.rport, e.sock.lport)] = (e.pids, e.peer)
    correct = pid_ok = peer_ok = missing = 0
    for k, (pids, cls, _ra) in truth.items():
        got = seen.get(k)
        if got is None:
            missing += 1
            continue
        pid_ok += got[0] == pids
        peer_ok += got[1] == cls
        correct += got[0] == pids and got[1] == cls
    decoys_reported = sum(1 for (ra, rp, lp) in seen if (ra, rp) in decoy_keys)
    extra = len(set(seen) - set(truth))
    for s in servers:
        s["w"].write("quit\n")
        s["w"].flush()
    for s in servers:
        os.waitpid(s["pid"], 0)
    return {"seed": SEED, "truth_sockets": len(truth), "correct": correct, "pid_ok": pid_ok,
            "peer_ok": peer_ok, "missing": missing, "extra_reported": extra,
            "decoys_reported": decoys_reported, "backend": snap.backend,
            "scan_seconds": round(scan_s, 4), "shared_child_pid": child,
            "by_class": {c: sum(1 for v in truth.values() if v[1] == c) for c in ADDRS}}


def main() -> dict:
    if os.environ.get("CW_IN_NETNS") == "1":
        return inner()
    env = dict(os.environ, CW_IN_NETNS="1")
    r = subprocess.run(["unshare", "-rn", sys.executable, os.path.abspath(__file__)],
                       env=env, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError("experimento B falló: " + r.stderr[-2000:])
    return json.loads(r.stdout.strip().splitlines()[-1])


if __name__ == "__main__":
    if os.environ.get("CW_IN_NETNS") == "1":
        print(json.dumps(inner()))
    else:
        print(json.dumps(main(), indent=2))

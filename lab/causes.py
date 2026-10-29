"""Experimento A del pre-registro: 3 repros x 3 corridas."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time

from closewait_scope.model import Tracker, take_snapshot

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def tree(pid: int) -> set[int]:
    pids = {pid}
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                with open(f"/proc/{d}/stat") as f:
                    ppid = int(f.read().rsplit(")", 1)[1].split()[1])
            except OSError:
                continue
            if ppid == pid:
                pids |= tree(int(d))
    return pids


def watch(pids_fn, seconds=6.0, interval=0.5) -> list[dict]:
    tr = Tracker()
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        tr.add(take_snapshot("auto", pids_fn()))
        time.sleep(interval)
    return tr.report()


def pick(rep: list[dict]) -> dict | None:
    return max(rep, key=lambda d: d["seen"]) if rep else None


def wait_port(port, t=10.0):
    end = time.monotonic() + t
    while time.monotonic() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"puerto {port} no abrió")


def run_noclose() -> dict:
    p = subprocess.Popen([PY, os.path.join(HERE, "repro_noclose.py")], stdout=subprocess.PIPE, text=True)
    port = int(p.stdout.readline())
    stop = threading.Event()

    def load():
        while not stop.is_set():
            c = socket.create_connection(("127.0.0.1", port))
            c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            c.recv(4096)
            c.close()
            time.sleep(0.05)
    th = threading.Thread(target=load)
    th.start()
    try:
        rep = watch(lambda: {p.pid})
    finally:
        stop.set()
        th.join()
        p.kill()
        p.wait()
    return pick(rep)


def run_gthread() -> dict:
    port = _free_port()
    gun = os.path.join(os.path.dirname(PY), "gunicorn")
    p = subprocess.Popen([gun, "-k", "gthread", "-w", "1", "--threads", "1", "-b", f"127.0.0.1:{port}",
                          "--chdir", HERE, "--timeout", "120", "gthread_app:app"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_port(port)
    time.sleep(0.5)
    stop = threading.Event()

    def client():
        try:
            c = socket.create_connection(("127.0.0.1", port))
            c.settimeout(0.3)
            c.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            try:
                c.recv(4096)
            except socket.timeout:
                pass
            c.close()
        except OSError:
            pass

    def load():
        for _ in range(20):
            if stop.is_set():
                break
            threading.Thread(target=client).start()
            time.sleep(0.25)
    th = threading.Thread(target=load)
    th.start()
    try:
        rep = watch(lambda: tree(p.pid))
    finally:
        stop.set()
        th.join()
        p.terminate()
        p.wait()
    return pick(rep)


def run_pool() -> dict:
    srv = subprocess.Popen([PY, os.path.join(HERE, "repro_pool_server.py")], stdout=subprocess.PIPE, text=True)
    port = int(srv.stdout.readline())
    cli = subprocess.Popen([PY, os.path.join(HERE, "repro_pool_client.py"), str(port)],
                           stdout=subprocess.PIPE, text=True)
    try:
        rep = watch(lambda: {cli.pid})
    finally:
        cli.kill()
        srv.kill()
        cli.wait()
        srv.wait()
    return pick(rep)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


REPROS = [("app_never_closes", run_noclose), ("worker_backlog_timeout", run_gthread),
          ("upstream_keepalive_pool", run_pool)]


def main(runs: int = 3) -> dict:
    out = {"repros": []}
    for expected, fn in REPROS:
        rr = []
        for i in range(runs):
            g = fn()
            got = g["cause"] if g else "sin_sockets"
            rr.append({"run": i + 1, "cause": got, "ok": got == expected,
                       "group": {k: g[k] for k in ("comm", "role", "peer_class", "seen", "left",
                                                   "current", "rxq_nonzero_frac", "leak_rate_per_s")} if g else None})
            print(f"[A] {expected} corrida {i + 1}: {got}", flush=True)
        out["repros"].append({"expected": expected, "runs": rr, "ok": all(r["ok"] for r in rr)})
    out["correct"] = sum(r["ok"] for r in out["repros"])
    out["total"] = len(REPROS)
    return out


if __name__ == "__main__":
    print(json.dumps(main(), indent=2, ensure_ascii=False))

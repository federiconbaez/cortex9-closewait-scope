"""CLI: snapshot | watch | compare | ebpf."""
from __future__ import annotations

import argparse
import json
import sys
import time

from .model import Tracker, compare, take_snapshot


def _pids(arg: str | None):
    return {int(p) for p in arg.split(",")} if arg else None


def cmd_watch(a) -> int:
    tr = Tracker()
    end = time.monotonic() + a.duration
    while True:
        tr.add(take_snapshot(a.backend, _pids(a.pid)))
        if time.monotonic() >= end:
            break
        time.sleep(a.interval)
    rep = tr.report()
    out = {"interval_s": a.interval, "duration_s": a.duration, "snapshots": tr.n, "groups": rep}
    _emit(out, a)
    return 0


def _emit(out: dict, a) -> None:
    if a.json:
        json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
        print()
        return
    groups = out.get("groups", [])
    if not groups:
        print("sin sockets en CLOSE_WAIT atribuibles")
        return
    print(f"{'PID':>7} {'COMM':<15} {'ROL':<7} {'PUERTO':>6} {'PEER':<9} {'AHORA':>6} {'FUGA/s':>7}  CAUSA")
    for g in groups:
        print(f"{g['pid']:>7} {g['comm'][:15]:<15} {g['role']:<7} {g['port']:>6} "
              f"{g['peer_class']:<9} {g['current']:>6} {g['leak_rate_per_s']:>7}  {g['cause']}")
        print(f"        edad (cota inferior): {g['age_hist_s']}")
        print(f"        -> {g['suggestion']}")


def cmd_compare(a) -> int:
    with open(a.before) as f:
        b = json.load(f)["groups"]
    with open(a.after) as f:
        c = json.load(f)["groups"]
    res = compare(b, c)
    json.dump(res, sys.stdout, indent=2, ensure_ascii=False)
    print()
    return 0


def cmd_ebpf(a) -> int:
    from .ebpf import run_bpftrace
    res = run_bpftrace(a.duration)
    json.dump(res, sys.stdout, indent=2)
    print()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="closewait-scope")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("snapshot", "watch"):
        s = sub.add_parser(name)
        s.add_argument("--backend", choices=["auto", "netlink", "proc"], default="auto")
        s.add_argument("--pid", help="lista de pids separados por coma")
        s.add_argument("--json", action="store_true")
        if name == "watch":
            s.add_argument("--interval", type=float, default=1.0)
            s.add_argument("--duration", type=float, default=10.0)
        else:
            s.set_defaults(interval=0.0, duration=0.0)
        s.set_defaults(fn=cmd_watch)
    c = sub.add_parser("compare")
    c.add_argument("before")
    c.add_argument("after")
    c.set_defaults(fn=cmd_compare)
    e = sub.add_parser("ebpf", help="edad exacta vía tracepoint sock:inet_sock_set_state (root)")
    e.add_argument("--duration", type=float, default=10.0)
    e.set_defaults(fn=cmd_ebpf)
    a = p.parse_args(argv)
    return a.fn(a)

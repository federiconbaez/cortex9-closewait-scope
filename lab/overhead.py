"""Experimento C del pre-registro: overhead a 10.000 conexiones/s.

Uso: python -m lab.overhead [--ebpf]   (--ebpf requiere root y bpftrace)
"""
from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BIN = os.path.join(HERE, "connload")
RATE, SECONDS, THREADS, PAIRS = 10000, 20, 8, 5


def build() -> None:
    subprocess.run(["gcc", "-O2", "-pthread", "-Wall", "-o", BIN, os.path.join(HERE, "connload.c")], check=True)


def load() -> dict:
    r = subprocess.run([BIN, str(RATE), str(SECONDS), str(THREADS)], capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def run_userspace_on() -> tuple[dict, float]:
    tool = subprocess.Popen([sys.executable, "-m", "closewait_scope", "watch", "--interval", "1",
                             "--duration", str(SECONDS + 1), "--json"], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(0.5)
    w = load()
    _, status, ru = os.wait4(tool.pid, 0)
    if status != 0:
        raise RuntimeError("la herramienta falló durante la carga: " + tool.stderr.read().decode()[-1000:])
    return w, ru.ru_utime + ru.ru_stime


def run_ebpf_on() -> tuple[dict, float, int]:
    sys.path.insert(0, ROOT)
    from closewait_scope.ebpf import Tracer
    tr = Tracer()
    c0 = tr.cpu_seconds()
    w = load()
    cpu = tr.cpu_seconds() - c0
    ev = tr.stop()
    return w, cpu, len(ev)


def main(ebpf: bool = False) -> dict:
    build()
    pairs = []
    for i in range(PAIRS):
        off = load()
        if ebpf:
            on, tool_cpu, nev = run_ebpf_on()
        else:
            on, tool_cpu = run_userspace_on()
            nev = None
        pairs.append({"off": off, "on": on, "tool_cpu_s": round(tool_cpu, 3), "ebpf_events": nev})
        print(f"[C] par {i + 1}: off {off['conn_per_s']}/s cpu {off['cpu_s']}s | on {on['conn_per_s']}/s "
              f"cpu {on['cpu_s']}s herramienta {tool_cpu:.3f}s", file=sys.stderr, flush=True)
    if ebpf:
        ov = [(p["on"]["cpu_s"] + p["tool_cpu_s"]) / p["off"]["cpu_s"] - 1 for p in pairs]
        formula = "(cpu_carga_con_sonda + cpu_bpftrace) / cpu_carga_sin_sonda - 1"
    else:
        ov = [p["tool_cpu_s"] / p["on"]["cpu_s"] for p in pairs]
        formula = "cpu_herramienta / cpu_carga_misma_corrida"
    return {"backend": "ebpf" if ebpf else "userspace", "formula": formula, "pairs": pairs,
            "overhead_median": round(statistics.median(ov), 4), "overhead_max": round(max(ov), 4),
            "overhead_all": [round(x, 4) for x in ov],
            "achieved_conn_per_s_min": min(min(p["off"]["conn_per_s"], p["on"]["conn_per_s"]) for p in pairs),
            "threshold": 0.02, "pass": statistics.median(ov) < 0.02}


if __name__ == "__main__":
    print(json.dumps(main("--ebpf" in sys.argv), indent=2))

"""Backend eBPF opcional (bpftrace sobre sock:inet_sock_set_state). Requiere root.

Falla con excepción si bpftrace no está o no puede adjuntarse: nunca devuelve un
resultado vacío como si hubiera medido.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ebpf", "closewait.bt")


class EbpfUnavailable(RuntimeError):
    pass


class Tracer:
    def __init__(self, script: str = SCRIPT) -> None:
        exe = shutil.which("bpftrace")
        if exe is None:
            raise EbpfUnavailable("bpftrace no está instalado")
        if os.geteuid() != 0:
            raise EbpfUnavailable("el backend eBPF requiere root")
        self.proc = subprocess.Popen([exe, script], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True)
        line = self.proc.stdout.readline()
        if not line.startswith("Attaching"):
            rest = self.proc.stdout.read() if self.proc.poll() is not None else ""
            self.proc.kill()
            raise EbpfUnavailable("bpftrace no adjuntó: " + line + rest)
        time.sleep(0.3)

    @property
    def pid(self) -> int:
        return self.proc.pid

    def stop(self) -> list[dict]:
        self.proc.send_signal(signal.SIGINT)
        out, _ = self.proc.communicate(timeout=30)
        return parse_events(out)


def parse_events(text: str) -> list[dict]:
    ev = []
    for line in text.splitlines():
        f = line.split()
        if f[:1] == ["ENTER"] and len(f) == 4:
            ev.append({"kind": "enter", "ns": int(f[1]), "sport": int(f[2]), "dport": int(f[3])})
        elif f[:1] == ["EXIT"] and len(f) == 5:
            ev.append({"kind": "exit", "ns": int(f[1]), "sport": int(f[2]), "dport": int(f[3]),
                       "dur_ns": int(f[4])})
    return ev


def run_bpftrace(duration: float) -> dict:
    tr = Tracer()
    time.sleep(duration)
    ev = tr.stop()
    return {"events": ev, "enters": sum(e["kind"] == "enter" for e in ev),
            "exits": sum(e["kind"] == "exit" for e in ev)}

"""Chequeo del backend eBPF (CI con sudo). No se descubre en tests.run: corre aparte y
falla con código distinto de 0 si bpftrace no adjunta o no ve la transición."""
import socket
import sys
import time

from closewait_scope.ebpf import Tracer


def main() -> int:
    tr = Tracer()  # lanza EbpfUnavailable si no hay root o bpftrace
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(4)
    port = ls.getsockname()[1]
    c = socket.create_connection(("127.0.0.1", port))
    s, _ = ls.accept()
    cport = c.getsockname()[1]
    c.close()            # servidor entra en CLOSE_WAIT
    time.sleep(0.5)
    s.close()            # servidor sale de CLOSE_WAIT
    time.sleep(0.3)
    ev = tr.stop()
    mine = [e for e in ev if e["sport"] == port and e["dport"] == cport]
    enters = [e for e in mine if e["kind"] == "enter"]
    exits = [e for e in mine if e["kind"] == "exit"]
    print(f"eventos totales {len(ev)}, del socket de prueba: {mine}")
    if len(enters) != 1 or len(exits) != 1:
        print("FALLA: se esperaba 1 ENTER y 1 EXIT")
        return 1
    dur = exits[0]["dur_ns"] / 1e9
    if not 0.4 <= dur <= 2.0:
        print(f"FALLA: duración {dur:.3f}s fuera de [0.4, 2.0]")
        return 1
    print(f"OK: CLOSE_WAIT medido por eBPF {dur:.3f}s (esperado ~0.5s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

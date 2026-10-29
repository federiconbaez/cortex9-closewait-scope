"""Corre los experimentos A, B y C (userspace) del pre-registro y escribe lab/out/results.json.

Sale con código 1 si algún experimento no puede correr. Un umbral no cumplido se
reporta como 'no cumplido' pero no oculta el número.
"""
import json
import os
import platform
import sys
import time

from lab import attribution, causes, overhead

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    res = {"host": {"kernel": platform.release(), "python": platform.python_version(),
                    "cpus": os.cpu_count()},
           "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    a = causes.main()
    res["A_causes"] = a
    b = attribution.main()
    b["accuracy"] = round(b["correct"] / b["truth_sockets"], 4)
    res["B_attribution"] = b
    print(f"[B] {b['correct']}/{b['truth_sockets']} correctos, señuelos reportados {b['decoys_reported']}", flush=True)
    c = overhead.main(ebpf=False)
    res["C_overhead_userspace"] = c
    res["verdicts"] = {
        "A (3/3)": "cumplido" if a["correct"] == 3 else "no cumplido",
        "B (>=95% de 1000)": "cumplido" if b["truth_sockets"] == 1000 and b["accuracy"] >= 0.95 else "no cumplido",
        "C userspace (<2%)": "cumplido" if c["pass"] else "no cumplido",
    }
    os.makedirs(os.path.join(HERE, "out"), exist_ok=True)
    with open(os.path.join(HERE, "out", "results.json"), "w") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print(json.dumps(res["verdicts"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

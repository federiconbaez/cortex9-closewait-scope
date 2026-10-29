"""Atribución socket -> proceso vía /proc/<pid>/fd y clasificación del peer."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "fc00::/7", "fe80::/10",
)]


def peer_class(addr: str) -> str:
    """loopback (proxy en la misma máquina), private (red interna) o public (resto).

    Decisión deliberada: los rangos de documentación (192.0.2/24, 198.51.100/24,
    203.0.113/24, 2001:db8::/32) cuentan como 'public', a diferencia de
    ipaddress.is_private. El laboratorio los usa como sustituto de internet.
    """
    ip = ipaddress.ip_address(addr)
    if ip.is_loopback:
        return "loopback"
    if any(ip in n for n in _PRIVATE_NETS if n.version == ip.version):
        return "private"
    return "public"


@dataclass(frozen=True)
class Proc:
    pid: int
    comm: str


def inode_owners(proc_root: str = "/proc", only_pids: set[int] | None = None) -> tuple[dict[int, list[Proc]], int]:
    """Mapa inode -> procesos que tienen el socket abierto. Devuelve también cuántos
    procesos no se pudieron inspeccionar (permisos)."""
    owners: dict[int, list[Proc]] = {}
    denied = 0
    pids = only_pids if only_pids is not None else (
        int(d) for d in os.listdir(proc_root) if d.isdigit())
    for pid in pids:
        fd_dir = os.path.join(proc_root, str(pid), "fd")
        try:
            fds = os.listdir(fd_dir)
        except PermissionError:
            denied += 1
            continue
        except (FileNotFoundError, ProcessLookupError, NotADirectoryError):
            continue
        comm = None
        for fd in fds:
            try:
                tgt = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if tgt.startswith("socket:["):
                ino = int(tgt[8:-1])
                if comm is None:
                    try:
                        with open(os.path.join(proc_root, str(pid), "comm")) as fh:
                            comm = fh.read().strip()
                    except OSError:
                        comm = "?"
                owners.setdefault(ino, []).append(Proc(pid, comm))
    return owners, denied

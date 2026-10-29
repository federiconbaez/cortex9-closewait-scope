"""Repro 1: servidor que lee el request, responde y nunca cierra (fuga de fd)."""
import socket
import sys
import time

ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", 0))
ls.listen(128)
print(ls.getsockname()[1], flush=True)
leaked = []
while True:
    c, _ = ls.accept()
    c.recv(4096)
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    leaked.append(c)  # bug sembrado: nunca c.close()

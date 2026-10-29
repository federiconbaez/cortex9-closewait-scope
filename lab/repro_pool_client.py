"""Repro 3, lado cliente: requests.Session con pool de 10, ráfaga y después ocioso."""
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests
from requests.adapters import HTTPAdapter

port = int(sys.argv[1])
s = requests.Session()
s.mount("http://", HTTPAdapter(pool_connections=1, pool_maxsize=10))
with ThreadPoolExecutor(10) as ex:
    list(ex.map(lambda _: s.get(f"http://127.0.0.1:{port}/").status_code, range(10)))
print("burst-done", flush=True)
time.sleep(3600)

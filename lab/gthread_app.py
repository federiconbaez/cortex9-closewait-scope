"""App WSGI para la repro 2: handler lento (2 s)."""
import time


def app(environ, start_response):
    time.sleep(2)
    start_response("200 OK", [("Content-Length", "2")])
    return [b"ok"]

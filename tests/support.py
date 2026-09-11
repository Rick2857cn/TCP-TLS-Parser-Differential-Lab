from contextlib import contextmanager
from threading import Thread
from lab.server import LocalServer, Handler as ServerHandler
from lab.client import send
from lab.firewall_naive import ALLOWED_IP


@contextmanager
def running(handler, **attrs):
    with LocalServer(0, handler) as server:
        for name, value in attrs.items():
            setattr(server, name, value)
        thread = Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=6)
            if thread.is_alive():
                raise RuntimeError('server thread failed to stop')


def exchange(handler, segments, mode='text', destination_ip=ALLOWED_IP):
    with running(ServerHandler, received=[]) as backend:
        with running(handler, upstream_port=backend.server_address[1], mode=mode,
                     destination_ip=destination_ip) as firewall:
            response = send(segments, firewall.server_address[1])
        return response, backend.received

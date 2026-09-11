import argparse
import socketserver
from .protocol import HOST, TIMEOUT, ProtocolError, encode_frame, read_segments


class LocalServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, port, handler):
        super().__init__((HOST, port), handler)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(TIMEOUT)
        try:
            segments = []
            for index, data in enumerate(read_segments(self.request), 1):
                print(f'[SERVER] segment #{index}: {data!r}', flush=True)
                segments.append(data)
            stream = b''.join(segments)
            print(f'[SERVER] reconstructed: {stream!r}', flush=True)
            if hasattr(self.server, 'received'):
                self.server.received.append(stream)
            self.request.sendall(encode_frame(b'SERVER_OK'))
        except (OSError, ProtocolError) as exc:
            print(f'[SERVER] incomplete/rejected: {exc}', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=19002)
    args = parser.parse_args()
    with LocalServer(args.port, Handler) as server:
        print(f'[SERVER] listening {server.server_address}', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()

"""故意错误：只检查当前数据块，不执行跨块重组。"""
import argparse
import socket
import socketserver
from .protocol import HOST, TIMEOUT, ProtocolError, encode_frame, read_frame, read_segments
from .server import LocalServer


def blocked(data, mode='text'):
    if mode == 'tls':
        from .tls_parser import extract_sni
        return extract_sni(data) == 'blocked.test'
    return b'blocked.test' in data


def decision(segments, mode='text'):
    return 'BLOCK' if any(blocked(s, mode) for s in segments) else 'PASS'


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(TIMEOUT)
        try:
            with socket.create_connection((HOST, self.server.upstream_port), TIMEOUT) as upstream:
                for data in read_segments(self.request):
                    verdict = decision([data], self.server.mode)
                    print(f'[NAIVE] segment: {data!r} -> {verdict}', flush=True)
                    if verdict == 'BLOCK':
                        self.request.sendall(encode_frame(b'BLOCK'))
                        return
                    upstream.sendall(encode_frame(data))
                upstream.sendall(encode_frame(b''))
                self.request.sendall(encode_frame(read_frame(upstream)))
        except (OSError, ProtocolError) as exc:
            print(f'[NAIVE] rejected: {exc}', flush=True)


def main(handler=Handler, default_port=19001):
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=default_port)
    parser.add_argument('--upstream-port', type=int, default=19002)
    parser.add_argument('--mode', choices=['text', 'tls'], default='text')
    args = parser.parse_args()
    with LocalServer(args.port, handler) as server:
        server.upstream_port = args.upstream_port
        server.mode = args.mode
        print(f'[FIREWALL] listening {server.server_address}', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()

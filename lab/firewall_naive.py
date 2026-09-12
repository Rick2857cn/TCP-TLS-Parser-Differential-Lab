"""故意错误：不规范化 IP 表示，也不执行跨块重组。"""
import argparse
import ipaddress
import socket
import socketserver
from .protocol import HOST, TIMEOUT, ProtocolError, encode_frame, read_frame, read_segments
from .server import LocalServer

BLOCKED_IP = '192.0.2.10'
ALLOWED_IP = '192.0.2.20'


def ip_blocked(destination_ip):
    return ipaddress.ip_address(destination_ip) == ipaddress.ip_address(BLOCKED_IP)


def blocked(data, mode='text'):
    if mode == 'tls':
        from .tls_parser import extract_sni
        return extract_sni(data) == 'blocked.test'
    return b'blocked.test' in data


def decision(segments, mode='text', destination_ip=ALLOWED_IP):
    return 'BLOCK' if ip_blocked(destination_ip) or any(blocked(s, mode) for s in segments) else 'PASS'


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(TIMEOUT)
        try:
            if ip_blocked(self.server.destination_ip):
                print(f'[NAIVE] destination IP {self.server.destination_ip} -> BLOCK', flush=True)
                # Drain framing bytes so Windows can deliver the teaching response before close.
                for _ in read_segments(self.request):
                    pass
                self.request.sendall(encode_frame(b'BLOCK'))
                return
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
    parser.add_argument('--simulated-destination-ip', default=ALLOWED_IP,
                        help='policy metadata only; no connection is made to this address')
    args = parser.parse_args()
    ipaddress.ip_address(args.simulated_destination_ip)
    with LocalServer(args.port, handler) as server:
        server.upstream_port = args.upstream_port
        server.mode = args.mode
        server.destination_ip = args.simulated_destination_ip
        print(f'[FIREWALL] listening {server.server_address}', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()

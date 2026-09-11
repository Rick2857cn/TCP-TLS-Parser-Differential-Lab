import socket
import socketserver
from .protocol import HOST, TIMEOUT, ProtocolError, encode_frame, read_frame, read_segments
from .firewall_naive import ALLOWED_IP, blocked, ip_blocked, main


def decision(segments, mode='text', destination_ip=ALLOWED_IP):
    if ip_blocked(destination_ip):
        return 'BLOCK'
    stream = b''.join(segments)
    if mode == 'tls':
        from .tls_parser import extract_sni
        sni = extract_sni(stream)
        # Fail closed for incomplete, malformed or missing SNI in this teaching policy.
        return 'BLOCK' if sni is None or sni == 'blocked.test' else 'PASS'
    return 'BLOCK' if blocked(stream) else 'PASS'


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(TIMEOUT)
        try:
            if ip_blocked(self.server.destination_ip):
                print(f'[REASSEMBLY] destination IP {self.server.destination_ip} -> BLOCK', flush=True)
                # The IP verdict is already final; drain without parsing application data.
                for _ in read_segments(self.request):
                    pass
                self.request.sendall(encode_frame(b'BLOCK'))
                return
            segments = list(read_segments(self.request))
            verdict = decision(segments, self.server.mode)
            print(f'[REASSEMBLY] {verdict}', flush=True)
            if verdict == 'BLOCK':
                self.request.sendall(encode_frame(b'BLOCK'))
                return
            with socket.create_connection((HOST, self.server.upstream_port), TIMEOUT) as upstream:
                for data in segments:
                    upstream.sendall(encode_frame(data))
                upstream.sendall(encode_frame(b''))
                self.request.sendall(encode_frame(read_frame(upstream)))
        except (OSError, ProtocolError) as exc:
            print(f'[REASSEMBLY] rejected: {exc}', flush=True)


if __name__ == '__main__':
    main(Handler, 19003)

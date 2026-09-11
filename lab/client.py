import argparse
import socket
from .protocol import HOST, TIMEOUT, encode_frame, read_frame


def send(segments, port=19001):
    wire = b''.join(encode_frame(s) for s in segments) + encode_frame(b'')
    with socket.create_connection((HOST, port), TIMEOUT) as sock:
        sock.sendall(wire)
        return read_frame(sock).decode('ascii')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=19001)
    parser.add_argument('--case', choices=['allowed', 'blocked', 'split'], default='split')
    args = parser.parse_args()
    cases = {'allowed': [b'allowed.test'], 'blocked': [b'blocked.test'],
             'split': [b'blocked.', b'test']}
    print(send(cases[args.case], args.port))


if __name__ == '__main__':
    main()

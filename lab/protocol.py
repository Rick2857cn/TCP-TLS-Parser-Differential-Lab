"""Length-prefixed teaching segments; empty frame explicitly ends a message."""
import struct

HOST = '127.0.0.1'
MAX_FRAME = 1024 * 1024
MAX_SEGMENTS = 4096
TIMEOUT = 5


class ProtocolError(ValueError):
    pass


def encode_frame(data: bytes) -> bytes:
    if len(data) > MAX_FRAME:
        raise ProtocolError('frame exceeds 1 MiB')
    return struct.pack('!I', len(data)) + data


def read_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ProtocolError('unexpected EOF before explicit message completion')
        result.extend(chunk)
    return bytes(result)


def read_frame(sock) -> bytes:
    size = struct.unpack('!I', read_exact(sock, 4))[0]
    if size > MAX_FRAME:
        raise ProtocolError('frame exceeds 1 MiB')
    return read_exact(sock, size)


def read_segments(sock):
    total = 0
    count = 0
    while True:
        data = read_frame(sock)
        if not data:
            return
        count += 1
        total += len(data)
        if total > MAX_FRAME or count > MAX_SEGMENTS:
            raise ProtocolError('message resource limit exceeded')
        yield data

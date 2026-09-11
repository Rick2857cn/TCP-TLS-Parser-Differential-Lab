"""Bounded educational ClientHello parser. Invalid/incomplete/no SNI -> None.

Supports handshake bytes fragmented across consecutive plaintext TLS records.
Not a TLS implementation or general-purpose production validator.
"""
MAX_INPUT = 1024 * 1024


class Invalid(ValueError):
    pass


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, count):
        if count < 0 or self.pos + count > len(self.data):
            raise Invalid('truncated vector')
        value = self.data[self.pos:self.pos + count]
        self.pos += count
        return value

    def number(self, count):
        return int.from_bytes(self.take(count), 'big')

    def vector(self, count):
        return self.take(self.number(count))

    def done(self):
        if self.pos != len(self.data):
            raise Invalid('trailing vector data')


def parse_body(body):
    r = Reader(body)
    if r.take(2) not in (b'\x03\x01', b'\x03\x02', b'\x03\x03'):
        raise Invalid('legacy version')
    r.take(32)
    if len(r.vector(1)) > 32:
        raise Invalid('session id')
    ciphers = r.vector(2)
    if not ciphers or len(ciphers) % 2:
        raise Invalid('cipher suites')
    if not r.vector(1):
        raise Invalid('compression methods')
    if r.pos == len(body):
        return None
    extensions = Reader(r.vector(2))
    r.done()
    seen = set()
    hostname = None
    while extensions.pos < len(extensions.data):
        kind = extensions.number(2)
        value = extensions.vector(2)
        if kind in seen:
            raise Invalid('duplicate extension')
        seen.add(kind)
        if kind != 0:
            continue
        outer = Reader(value)
        names = Reader(outer.vector(2))
        outer.done()
        if not names.data:
            raise Invalid('empty server name list')
        name_types = set()
        while names.pos < len(names.data):
            name_type = names.number(1)
            raw = names.vector(2)
            if name_type in name_types or not raw:
                raise Invalid('invalid server name')
            name_types.add(name_type)
            if name_type != 0:
                raise Invalid('unsupported name type')
            hostname = raw.decode('ascii').lower()
            if len(hostname) > 253 or any(
                not label or len(label) > 63 or label.startswith('-') or label.endswith('-')
                or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in label)
                for label in hostname.split('.')
            ):
                raise Invalid('invalid hostname')
    return hostname


def extract_sni(data: bytes) -> str | None:
    if len(data) > MAX_INPUT:
        return None
    try:
        records = Reader(data)
        handshake = bytearray()
        while records.pos < len(data):
            if records.number(1) != 22:
                raise Invalid('expected handshake record')
            if records.take(2) not in (b'\x03\x01', b'\x03\x02', b'\x03\x03'):
                raise Invalid('record version')
            size = records.number(2)
            if not 0 < size <= 16384:
                raise Invalid('record length')
            handshake.extend(records.take(size))
            if len(handshake) >= 4:
                if handshake[0] != 1:
                    raise Invalid('expected ClientHello')
                length = int.from_bytes(handshake[1:4], 'big')
                if length > MAX_INPUT - 4:
                    raise Invalid('handshake too large')
                if len(handshake) >= length + 4:
                    # This lab accepts exactly one ClientHello and no trailing records.
                    if len(handshake) != length + 4:
                        raise Invalid('extra handshake bytes')
                    records.done()
                    return parse_body(bytes(handshake[4:]))
    except (Invalid, UnicodeError):
        return None
    return None

import random
import unittest
from lab.tls_clienthello import generate_client_hello
from lab.tls_parser import extract_sni
from lab.firewall_naive import Handler as Naive, decision as naive
from lab.firewall_reassembly import Handler as Reassembly, decision as reassembly
from tests.support import exchange


class TLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hello = generate_client_hello('blocked.test')

    def test_real_record(self):
        self.assertEqual(self.hello[0], 22)
        self.assertEqual(int.from_bytes(self.hello[3:5], 'big'), len(self.hello) - 5)
        self.assertEqual(extract_sni(self.hello), 'blocked.test')
        self.assertEqual(extract_sni(generate_client_hello('allowed.test')), 'allowed.test')

    def test_all_truncations(self):
        for end in range(len(self.hello)):
            self.assertIsNone(extract_sni(self.hello[:end]))

    def test_split(self):
        cut = self.hello.index(b'blocked.test') + len(b'blocked.')
        segments = [self.hello[:cut], self.hello[cut:]]
        self.assertTrue(all(extract_sni(s) is None for s in segments))
        self.assertEqual(naive(segments, 'tls'), 'PASS')
        self.assertEqual(reassembly(segments, 'tls'), 'BLOCK')
        for handler, expected in ((Naive, 'SERVER_OK'), (Reassembly, 'BLOCK')):
            result, received = exchange(handler, segments, 'tls')
            self.assertEqual(result, expected)
            self.assertEqual(received, [self.hello] if expected == 'SERVER_OK' else [])

    def test_tls_whole_network(self):
        for hostname, expected in [('blocked.test', 'BLOCK'), ('allowed.test', 'SERVER_OK')]:
            for handler in (Naive, Reassembly):
                self.assertEqual(exchange(handler, [generate_client_hello(hostname)], 'tls')[0], expected)

    def test_record_fragmentation(self):
        payload = self.hello[5:]
        for split in (1, 3, 20, len(payload) - 1):
            records = b''.join(b'\x16\x03\x03' + len(p).to_bytes(2, 'big') + p
                               for p in (payload[:split], payload[split:]))
            self.assertEqual(extract_sni(records), 'blocked.test')

    def test_malformed(self):
        rng = random.Random(7)
        for _ in range(500):
            self.assertIsNone(extract_sni(rng.randbytes(rng.randrange(200))))
        for position in (0, 1, 3, 5, 6, 7, 8):
            data = bytearray(self.hello)
            data[position] = 255
            self.assertIsNone(extract_sni(bytes(data)))
        self.assertIsNone(extract_sni(self.hello + b'extra'))
        self.assertEqual(reassembly([b'invalid'], 'tls'), 'BLOCK')

    def test_hostname_scope(self):
        for name in ('example.com', 'localhost', 'bad..test', '-bad.test'):
            with self.assertRaises(ValueError):
                generate_client_hello(name)

    def test_nested_lengths_and_duplicates(self):
        def vector(data, width=2):
            return len(data).to_bytes(width, 'big') + data

        def wrap(extensions):
            body = b'\x03\x03' + b'R' * 32 + b'\x00' + vector(b'\x13\x01') + b'\x01\x00' + vector(extensions)
            handshake = b'\x01' + vector(body, 3)
            return b'\x16\x03\x03' + vector(handshake)

        name = b'\x00' + vector(b'blocked.test')
        sni = b'\x00\x00' + vector(vector(name))
        self.assertEqual(extract_sni(wrap(sni)), 'blocked.test')
        self.assertIsNone(extract_sni(wrap(b'')))
        self.assertIsNone(extract_sni(wrap(sni + sni)))
        for malformed in (b'\x00', b'\x00\x00\xff\xff',
                          b'\x00\x00' + vector(b'\xff\xff' + name),
                          b'\x00\x00' + vector(vector(b'\x00\xff\xffbad')),
                          b'\x00\x00' + vector(vector(name + name))):
            self.assertIsNone(extract_sni(wrap(malformed)))

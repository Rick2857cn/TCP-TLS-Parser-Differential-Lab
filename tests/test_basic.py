import struct
import unittest
from lab.protocol import MAX_FRAME, ProtocolError, encode_frame, read_frame
from lab.protocol import read_segments
from lab.firewall_naive import decision


class PartialSocket:
    def __init__(self, data):
        self.data = data

    def recv(self, count):
        chunk, self.data = self.data[:min(count, 1)], self.data[min(count, 1):]
        return chunk


class BasicTests(unittest.TestCase):
    def test_partial_recv(self):
        self.assertEqual(read_frame(PartialSocket(encode_frame(b'abc'))), b'abc')

    def test_network_order(self):
        self.assertEqual(encode_frame(b'abc')[:4], b'\x00\x00\x00\x03')

    def test_limits(self):
        with self.assertRaises(ProtocolError):
            read_frame(PartialSocket(struct.pack('!I', MAX_FRAME + 1)))
        with self.assertRaises(ProtocolError):
            encode_frame(b'x' * (MAX_FRAME + 1))

    def test_eof(self):
        for data in (b'', b'\x00', encode_frame(b'abc')[:-1]):
            with self.assertRaises(ProtocolError):
                read_frame(PartialSocket(data))

    def test_empty_end(self):
        self.assertEqual(read_frame(PartialSocket(encode_frame(b''))), b'')

    def test_naive_cases(self):
        for segments, expected in [([b'allowed.test'], 'PASS'), ([b'blocked.test'], 'BLOCK'),
                                   ([b'blocked.', b'test'], 'PASS')]:
            self.assertEqual(decision(segments), expected)

    def test_segment_count_limit(self):
        sock = PartialSocket(encode_frame(b'x') * 4097 + encode_frame(b''))
        with self.assertRaises(ProtocolError):
            list(read_segments(sock))

import unittest
from lab.firewall_naive import Handler as Naive
from lab.firewall_reassembly import Handler as Reassembly
from tests.support import exchange


class ReassemblyTests(unittest.TestCase):
    def test_loopback_matrix(self):
        cases = [([b'allowed.test'], 'SERVER_OK', 'SERVER_OK'),
                 ([b'blocked.test'], 'BLOCK', 'BLOCK'),
                 ([b'blocked.', b'test'], 'SERVER_OK', 'BLOCK'),
                 ([b'blo', b'cked', b'.test'], 'SERVER_OK', 'BLOCK'),
                 ([b'allo', b'wed.', b'test'], 'SERVER_OK', 'SERVER_OK')]
        for segments, naive, reassembly in cases:
            for handler, expected in [(Naive, naive), (Reassembly, reassembly)]:
                with self.subTest(segments=segments, handler=handler.__module__):
                    result, received = exchange(handler, segments)
                    self.assertEqual(result, expected)
                    self.assertEqual(received, [b''.join(segments)] if expected == 'SERVER_OK' else [])

    def test_late_block_no_complete_message(self):
        for handler in (Naive, Reassembly):
            result, received = exchange(handler, [b'prefix', b'blocked.test'])
            self.assertEqual(result, 'BLOCK')
            self.assertEqual(received, [])

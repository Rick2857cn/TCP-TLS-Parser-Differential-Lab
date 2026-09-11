import unittest
from lab.sequence import Segment, reconstruct


class SequenceTests(unittest.TestCase):
    def test_out_of_order(self):
        self.assertEqual(reconstruct([Segment(6, b'GHI'), Segment(0, b'ABC'), Segment(3, b'DEF')], 9),
                         (b'ABCDEFGHI', 'COMPLETE'))

    def test_gap(self):
        result, status = reconstruct([Segment(0, b'ABC'), Segment(6, b'GHI')])
        self.assertEqual(result, b'ABC')
        self.assertIn('expected next seq = 3, actual = 6', status)

    def test_unknown_tail(self):
        self.assertIn('END UNKNOWN', reconstruct([Segment(0, b'ABC')])[1])
        self.assertIn('GAP DETECTED', reconstruct([Segment(0, b'ABC')], 6)[1])

    def test_overlap(self):
        self.assertEqual(reconstruct([Segment(0, b'ABC'), Segment(0, b'ABC')], 3)[0], b'ABC')
        with self.assertRaises(ValueError):
            reconstruct([Segment(0, b'ABC'), Segment(1, b'X')])

"""Pure in-memory byte offsets, not real TCP sequence numbers or packets."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Segment:
    seq: int
    payload: bytes


def reconstruct(segments, expected_length=None):
    cells = {}
    for segment in segments:
        if segment.seq < 0 or segment.seq + len(segment.payload) > 1024 * 1024:
            raise ValueError('sequence outside teaching buffer')
        for offset, byte in enumerate(segment.payload, segment.seq):
            if offset in cells and cells[offset] != byte:
                raise ValueError('conflicting overlap')
            cells[offset] = byte
    end = max(cells, default=-1) + 1
    if expected_length is not None:
        if not 0 <= expected_length <= 1024 * 1024 or end > expected_length:
            raise ValueError('invalid expected length')
        end = expected_length
    result = bytearray()
    for offset in range(end):
        if offset not in cells:
            actual = next((p for p in sorted(cells) if p > offset), None)
            return bytes(result), f'GAP DETECTED: expected next seq = {offset}, actual = {actual}'
        result.append(cells[offset])
    return bytes(result), 'COMPLETE' if expected_length is not None else 'CONTIGUOUS; END UNKNOWN'

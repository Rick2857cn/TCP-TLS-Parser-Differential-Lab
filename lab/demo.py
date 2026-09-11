"""Self-cleaning real loopback demo, with assertions on server observations."""
from .firewall_naive import Handler as Naive
from .firewall_reassembly import Handler as Reassembly
from .tls_clienthello import generate_client_hello
from .tls_parser import extract_sni
from .sequence import Segment, reconstruct
from tests.support import exchange


def main():
    hello = generate_client_hello('blocked.test')
    assert extract_sni(hello) == 'blocked.test'
    cut = hello.index(b'blocked.test') + len(b'blocked.')
    split = [hello[:cut], hello[cut:]]
    assert all(extract_sni(part) is None for part in split)
    cases = [('allowed.test', [b'allowed.test'], 'text', ('PASS', 'PASS')),
             ('blocked.test', [b'blocked.test'], 'text', ('BLOCK', 'BLOCK')),
             ('blocked. + test', [b'blocked.', b'test'], 'text', ('PASS', 'BLOCK')),
             ('TLS SNI whole', [hello], 'tls', ('BLOCK', 'BLOCK')),
             ('TLS SNI split', split, 'tls', ('PASS', 'BLOCK'))]
    rows = []
    for label, segments, mode, expected in cases:
        verdicts = []
        for handler, target in zip((Naive, Reassembly), expected):
            response, received = exchange(handler, segments, mode)
            verdict = 'PASS' if response == 'SERVER_OK' else response
            assert verdict == target, (label, verdict, target)
            assert received == ([b''.join(segments)] if target == 'PASS' else [])
            verdicts.append('MISSED' if label == 'TLS SNI split' and verdict == 'PASS' else verdict)
        rows.append((label, *verdicts))
    print('\nSequence out of order:', reconstruct([Segment(6, b'GHI'), Segment(0, b'ABC'), Segment(3, b'DEF')], 9))
    print('Sequence missing:', reconstruct([Segment(0, b'ABC'), Segment(6, b'GHI')]))
    print('Sequence unknown tail:', reconstruct([Segment(0, b'ABC')]))
    print('\n' + '=' * 60)
    print('Campus Firewall Parser Differential Lab')
    print(f'{"TEST":28} {"NAIVE":12} REASSEMBLY')
    print('-' * 60)
    for label, naive, reassembly in rows:
        print(f'{label:28} {naive:12} {reassembly}')
    print('=' * 60)
    print('Same logical data, different parser views. All assertions passed.')


if __name__ == '__main__':
    main()

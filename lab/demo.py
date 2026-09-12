"""Self-cleaning real loopback demo, with assertions on server observations."""
from .firewall_naive import ALLOWED_IP, BLOCKED_IP, Handler as Naive
from .firewall_reassembly import Handler as Reassembly
from .tls_clienthello import generate_client_hello
from .tls_parser import extract_sni
from .sequence import Segment, reconstruct
from tests.support import exchange


def main():
    mapped_blocked_ip = '::ffff:192.0.2.10'
    hello = generate_client_hello('blocked.test')
    assert extract_sni(hello) == 'blocked.test'
    cut = hello.index(b'blocked.test') + len(b'blocked.')
    split = [hello[:cut], hello[cut:]]
    assert all(extract_sni(part) is None for part in split)
    allowed_hello = generate_client_hello('allowed.test')
    cases = [('allowed.test', [b'allowed.test'], 'text', ALLOWED_IP, ('PASS', 'PASS')),
             ('blocked.test', [b'blocked.test'], 'text', ALLOWED_IP, ('BLOCK', 'BLOCK')),
             ('blocked. + test', [b'blocked.', b'test'], 'text', ALLOWED_IP, ('PASS', 'BLOCK')),
             ('TLS allowed IP + allowed SNI', [allowed_hello], 'tls', ALLOWED_IP, ('PASS', 'PASS')),
             ('TLS allowed IP + blocked SNI', [hello], 'tls', ALLOWED_IP, ('BLOCK', 'BLOCK')),
             ('TLS blocked IP + allowed SNI', [allowed_hello], 'tls', BLOCKED_IP, ('BLOCK', 'BLOCK')),
             ('TLS allowed IP + split SNI', split, 'tls', ALLOWED_IP, ('PASS', 'BLOCK')),
             ('TLS blocked IP + split SNI', split, 'tls', BLOCKED_IP, ('BLOCK', 'BLOCK')),
             ('TLS mapped blocked IP + allowed SNI', [allowed_hello], 'tls', mapped_blocked_ip, ('PASS', 'BLOCK')),
             ('TLS mapped blocked IP + split SNI', split, 'tls', mapped_blocked_ip, ('PASS', 'BLOCK'))]
    rows = []
    for label, segments, mode, destination_ip, expected in cases:
        verdicts = []
        for handler, target in zip((Naive, Reassembly), expected):
            response, received = exchange(handler, segments, mode, destination_ip)
            verdict = 'PASS' if response == 'SERVER_OK' else response
            assert verdict == target, (label, verdict, target)
            assert received == ([b''.join(segments)] if target == 'PASS' else [])
            missed = label == 'TLS allowed IP + split SNI' or label.startswith('TLS mapped blocked IP')
            verdicts.append('MISSED' if missed and verdict == 'PASS' else verdict)
        rows.append((label, *verdicts))
    print('\nSequence out of order:', reconstruct([Segment(6, b'GHI'), Segment(0, b'ABC'), Segment(3, b'DEF')], 9))
    print('Sequence missing:', reconstruct([Segment(0, b'ABC'), Segment(6, b'GHI')]))
    print('Sequence unknown tail:', reconstruct([Segment(0, b'ABC')]))
    print('\n' + '=' * 72)
    print('Campus Firewall Parser Differential Lab')
    print(f'{"TEST":36} {"NAIVE":12} REASSEMBLY')
    print('-' * 72)
    for label, naive, reassembly in rows:
        print(f'{label:36} {naive:12} {reassembly}')
    print('=' * 72)
    print('Same logical data, different parser views. All assertions passed.')
    print('The composed bypass needs both an IP canonicalization bug and an SNI reassembly bug.')


if __name__ == '__main__':
    main()

"""Generate real TLS bytes entirely in memory; never creates a socket."""
import ssl


def generate_client_hello(hostname: str) -> bytes:
    hostname = hostname.lower()
    if not hostname.endswith('.test') or len(hostname) > 253:
        raise ValueError('only .test hostnames are permitted')
    labels = hostname.split('.')
    if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-')
           or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in label)
           for label in labels):
        raise ValueError('invalid ASCII test hostname')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_hostname=hostname)
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()

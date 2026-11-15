"""
Write the vector files of asm-quic.

Usage: python3 -I vectors.py OUT_DIR

Expected results:
- rfc9001.bin: RFC 9001 appendix A, the official values.
- packet-generated.bin: generated cases, with expected results from the
  pinned `cryptography` package (OpenSSL) and the steps of RFC 9001
  section 5 written out here. The script checks that these steps give the
  official values of appendix A first.
- libp2p-tls.bin: the 4 certificates of libp2p/specs tls/tls.md; the peer
  IDs of the spec must match the host keys that the checks give.
- cert-generated.bin: certificates made with `cryptography`, with the checks
  of the libp2p TLS spec written out here (ref_cert).
The file format is in README.md.
"""

import base64
import datetime
import hashlib
import os
import random
import re
import struct
import sys
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RFC = "https://www.rfc-editor.org/rfc/"
SOURCES = {
    "rfc9001.txt": (RFC + "rfc9001.txt", "3bbaecdf5afd278052a2c48348ce118c4ff8d0cf6b9915549858171b3f98a591"),
    "tls.md": ("https://raw.githubusercontent.com/libp2p/specs/c750236de43cd8b246a824b377dfdb26bae686db/tls/tls.md",
               "0478417f1d37a85501845f38369fb4b979b1a7be0d639174933bed7e33cce908"),
}

# include/quic.inc
OK, INVALID_ARGUMENT, INVALID_PACKET, DECRYPT_FAILED, INVALID_CERT = 0, 2, 3, 4, 5
NONE = (1 << 64) - 1
MAX_PACKET = 1500
HEADER_MAX, SEALED_MAX = 256, 1520

KIND_INITIAL_KEYS, KIND_SEAL, KIND_OPEN, KIND_RETRY_TAG, KIND_CERT = 1, 2, 3, 4, 5
CERT_P256, CERT_ED25519 = 1, 2
KEY_RSA, KEY_ED25519, KEY_SECP256K1, KEY_ECDSA = 0, 1, 2, 3
CERT_MAX, HOST_MAX = 2048, 128
LIBP2P_OID = x509.ObjectIdentifier("1.3.6.1.4.1.53594.1.1")
# Extensions that go-libp2p's x509 parser handles, so they may be critical:
# subjectKeyIdentifier, keyUsage, subjectAltName, basicConstraints,
# authorityKeyIdentifier, extKeyUsage.
UNDERSTOOD = {"2.5.29.14", "2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.35", "2.5.29.37"}
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
RETRY_KEY = bytes.fromhex("be0c690b9f66575a1d766b54e368c84e")
RETRY_NONCE = bytes.fromhex("461599d35d632bf2239825bb")


def fail(text):
    sys.exit("vectors.py: " + text)


def fetch(out, name):
    url, sha = SOURCES[name]
    path = os.path.join(out, "sources", name)
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() == sha:
            return data
    request = urllib.request.Request(url, headers={"User-Agent": "asm-quic-vector-generator"})
    with urllib.request.urlopen(request) as r:
        data = r.read()
    if hashlib.sha256(data).hexdigest() != sha:
        fail(f"{name}: SHA-256 {hashlib.sha256(data).hexdigest()}, pinned {sha}")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return data


def u64(v):
    return struct.pack("<Q", v)


def blob(b):
    return u64(len(b)) + bytes(b)


class VectorFile:
    def __init__(self):
        self.cases = []

    def add(self, kind, name, body):
        self.cases.append(u64(kind) + blob(name.encode()) + body)

    def write(self, path):
        with open(path, "wb") as f:
            f.write(b"QUICVEC1" + u64(len(self.cases)))
            for c in self.cases:
                f.write(c)


# ---------------------------------------------------------------- RFC 9001 section 5, written out


def hkdf_extract(salt, ikm):
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def hkdf_expand_label(secret, label, context, length):
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    out, t, i = b"", b"", 1
    while len(out) < length:
        h = hmac.HMAC(secret, hashes.SHA256())
        h.update(t + info + bytes([i]))
        t = h.finalize()
        out += t
        i += 1
    return out[:length]


def packet_keys(secret):
    """PacketKeys: key, IV and 4 zero bytes, header protection key."""
    key = hkdf_expand_label(secret, b"quic key", b"", 16)
    iv = hkdf_expand_label(secret, b"quic iv", b"", 12)
    hp = hkdf_expand_label(secret, b"quic hp", b"", 16)
    return key + iv + bytes(4) + hp


def initial_keys(dcid):
    initial = hkdf_extract(INITIAL_SALT, dcid)
    client = hkdf_expand_label(initial, b"client in", b"", 32)
    server = hkdf_expand_label(initial, b"server in", b"", 32)
    return packet_keys(client) + packet_keys(server)


def hp_mask(hp, sample):
    return Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)


def seal(keys, pn, header, payload):
    key, iv, hp = keys[:16], keys[16:28], keys[32:48]
    nonce = bytes(a ^ b for a, b in zip(iv, bytes(4) + pn.to_bytes(8, "big")))
    packet = bytearray(header + AESGCM(key).encrypt(nonce, payload, header))
    pn_len = (header[0] & 3) + 1
    pn_off = len(header) - pn_len
    mask = hp_mask(hp, bytes(packet[pn_off + 4: pn_off + 20]))
    packet[0] ^= mask[0] & (0x0F if packet[0] & 0x80 else 0x1F)
    for i in range(pn_len):
        packet[pn_off + i] ^= mask[1 + i]
    return bytes(packet)


def pn_decode(truncated, bits, largest):
    expected = 0 if largest == NONE else largest + 1
    win = 1 << bits
    hwin = win // 2
    mask = win - 1
    candidate = (expected & ~mask) | truncated
    if candidate <= expected - hwin and candidate < (1 << 62) - win:
        return candidate + win
    if candidate > expected + hwin and candidate >= win:
        return candidate - win
    return candidate


def open_packet(keys, pn_off, largest, packet):
    """(status, pn, header, payload) as quic_packet_open gives them."""
    key, iv, hp = keys[:16], keys[16:28], keys[32:48]
    if pn_off >= len(packet) or pn_off + 20 > len(packet) or len(packet) > HEADER_MAX + SEALED_MAX:
        return INVALID_PACKET, 0, b"", b""
    p = bytearray(packet)
    mask = hp_mask(hp, bytes(p[pn_off + 4: pn_off + 20]))
    p[0] ^= mask[0] & (0x0F if p[0] & 0x80 else 0x1F)
    pn_len = (p[0] & 3) + 1
    for i in range(pn_len):
        p[pn_off + i] ^= mask[1 + i]
    truncated = int.from_bytes(p[pn_off: pn_off + pn_len], "big")
    pn = pn_decode(truncated, 8 * pn_len, largest)
    hlen = pn_off + pn_len
    sealed = bytes(p[hlen:])
    if len(sealed) < 16 or hlen > HEADER_MAX or len(sealed) > SEALED_MAX:
        return INVALID_PACKET, 0, b"", b""
    nonce = bytes(a ^ b for a, b in zip(iv, bytes(4) + pn.to_bytes(8, "big")))
    try:
        payload = AESGCM(key).decrypt(nonce, sealed, bytes(p[:hlen]))
    except Exception:
        return DECRYPT_FAILED, 0, b"", b""
    return OK, pn, bytes(p[:hlen]), payload


def retry_tag(odcid, retry):
    pseudo = bytes([len(odcid)]) + odcid + retry
    return AESGCM(RETRY_KEY).encrypt(RETRY_NONCE, b"", pseudo)


# ---------------------------------------------------------------- Cases


def initial_case(f, name, dcid, want=None):
    if len(dcid) > 20:
        f.add(KIND_INITIAL_KEYS, name, blob(dcid) + u64(INVALID_ARGUMENT) + bytes(96))
        return
    keys = initial_keys(dcid)
    if want is not None and keys != want:
        fail(f"{name}: the steps of section 5.2 do not give the official keys")
    f.add(KIND_INITIAL_KEYS, name, blob(dcid) + u64(OK) + keys)


def seal_status(header, payload):
    if not header or len(header) > HEADER_MAX or len(payload) > SEALED_MAX - 16:
        return INVALID_ARGUMENT
    pn_len = (header[0] & 3) + 1
    if pn_len > len(header) or pn_len + len(payload) < 4:
        return INVALID_ARGUMENT
    return OK


def seal_case(f, name, keys, pn, header, payload, want=None):
    status = seal_status(header, payload)
    sealed = seal(keys, pn, header, payload) if status == OK else b""
    if want is not None and sealed != want:
        fail(f"{name}: the steps of section 5 do not give the official packet")
    f.add(KIND_SEAL, name, keys + u64(pn) + blob(header) + blob(payload) + u64(status) + blob(sealed))
    return sealed


def open_case(f, name, keys, pn_off, largest, packet, want=None):
    status, pn, header, payload = open_packet(keys, pn_off, largest, packet)
    if want is not None and (status, pn, header, payload) != want:
        fail(f"{name}: the steps of section 5 do not give the official payload")
    f.add(KIND_OPEN, name, keys + u64(pn_off) + u64(largest) + blob(packet) + u64(status) + u64(pn) +
          blob(header) + blob(payload))


def retry_case(f, name, odcid, retry, want=None):
    tag = retry_tag(odcid, retry)
    if want is not None and tag != want:
        fail(f"{name}: the steps of section 5.8 do not give the official tag")
    f.add(KIND_RETRY_TAG, name, blob(odcid) + blob(retry) + u64(OK) + tag)


def hexes(text):
    return bytes.fromhex(re.sub(r"\s+", "", text))


def appendix_a(text):
    """The values of RFC 9001 appendix A.1 to A.4."""
    a = text[text.index("Appendix A.  Sample Packet Protection\n\n   This"):
             text.index("A.5.  ChaCha20-Poly1305 Short Header Packet\n\n   This")]
    hexrun = re.compile(r"=\s*([0-9a-f]{8,}(?:\s+[0-9a-f]{8,})*)")

    def after(anchor, start=0):
        i = a.index(anchor, start) + len(anchor)
        m = hexrun.search(a, i)
        if not m:
            fail(f"rfc 9001: no value after {anchor}")
        return hexes(m.group(1)), m.end()

    def block(start, end):
        s = a.index(start) + len(start)
        return hexes(a[s:a.index(end, s)])

    v = {}
    p = 0
    for side in ("client", "server"):
        v[side + "_secret"], p = after(side + "_initial_secret\n", p)
        for name in ("key", "iv", "hp"):
            v[side + "_" + name], p = after(f'HKDF-Expand-Label({side}_initial_secret, "quic {name}"', p)
    v["client_crypto"] = block("frames to make a 1162-byte payload:\n", "The unprotected header")
    v["client_header"] = block("a packet number of 2:\n", "Protecting the payload")
    v["client_packet"] = block("The resulting protected packet is:\n", "A.3.  Server Initial")
    v["server_payload"] = block("and no PADDING frames:\n", "The header from the server")
    v["server_header"] = block("for a packet number of 1:\n", "As a result")
    v["server_packet"] = block("The final protected packet is then:\n", "A.4.  Retry")
    v["retry"] = block("not included in the final Retry packet:\n", "\n\n")
    return v

# ---------------------------------------------------------------- libp2p TLS certificates


def der(tag, content):
    n = len(content)
    if n < 128:
        head = bytes([n])
    elif n < 256:
        head = bytes([0x81, n])
    else:
        head = bytes([0x82, n >> 8, n & 0xFF])
    return bytes([tag]) + head + content


def der_items(b):
    """The (tag, content) elements of a DER content."""
    out, i = [], 0
    while i < len(b):
        tag, n = b[i], b[i + 1]
        i += 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(b[i: i + k], "big")
            i += k
        out.append((tag, b[i: i + n]))
        i += n
    return out


def b58(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def peer_id(proto):
    mh = b"\x00" + bytes([len(proto)]) + proto if len(proto) <= 42 else b"\x12\x20" + hashlib.sha256(proto).digest()
    return b58(mh)


def pb_key(proto):
    """(type, data) of a PublicKey protobuf with one-byte varints, or None."""
    i, typ, data = 0, None, None
    while i < len(proto):
        if proto[i] == 0x08 and typ is None and i + 1 < len(proto) and proto[i + 1] < 128:
            typ, i = proto[i + 1], i + 2
        elif proto[i] == 0x12 and data is None and i + 1 < len(proto) and proto[i + 1] < 128 and \
                i + 2 + proto[i + 1] <= len(proto):
            data, i = proto[i + 2: i + 2 + proto[i + 1]], i + 2 + proto[i + 1]
        else:
            return None
    return None if typ is None or data is None else (typ, data)


def host_ok(typ, data, sig, msg):
    try:
        if typ == KEY_ED25519 and len(data) == 32 and len(sig) == 64:
            ed25519.Ed25519PublicKey.from_public_bytes(data).verify(sig, msg)
            return True
        if typ == KEY_SECP256K1 and len(data) == 33:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), data).verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        if typ == KEY_ECDSA:
            k = serialization.load_der_public_key(data)
            if isinstance(k, ec.EllipticCurvePublicKey) and k.curve.name == "secp256r1":
                k.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
                return True
    except Exception:
        pass
    return False


def ref_cert(data, now):
    """(kind, key, host key protobuf) when the certificate meets the libp2p TLS checks of asm-quic, else None."""
    if len(data) > CERT_MAX:
        return None
    try:
        cert = x509.load_der_x509_certificate(data)
        if cert.public_bytes(serialization.Encoding.DER) != data:
            return None
        if not cert.not_valid_before_utc.timestamp() <= now <= cert.not_valid_after_utc.timestamp():
            return None
        pk = cert.public_key()
        alg = cert.signature_algorithm_oid
        if isinstance(pk, ec.EllipticCurvePublicKey) and pk.curve.name == "secp256r1":
            kind = CERT_P256
            key = pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            if alg != x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256:
                return None
            pk.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pk, ed25519.Ed25519PublicKey):
            kind = CERT_ED25519
            key = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if alg != x509.SignatureAlgorithmOID.ED25519:
                return None
            pk.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return None
        exts = cert.extensions
    except Exception:
        return None
    found = [e for e in exts if e.oid == LIBP2P_OID]
    if len(found) != 1:
        return None
    if any(e.critical and e.oid != LIBP2P_OID and e.oid.dotted_string not in UNDERSTOOD for e in exts):
        return None
    items = der_items(found[0].value.value)
    if len(items) != 1 or items[0][0] != 0x30:
        return None
    inner = der_items(items[0][1])
    if len(inner) != 2 or inner[0][0] != 4 or inner[1][0] != 4 or len(inner[0][1]) > HOST_MAX:
        return None
    proto, sig = inner
    proto, sig = proto[1], sig[1]
    k = pb_key(proto)
    spki = pk.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if k is None or not host_ok(k[0], k[1], sig, b"libp2p-tls-handshake:" + spki):
        return None
    return kind, key, proto


def cert_case(f, name, data, now, want=None):
    r = ref_cert(data, now)
    if want is not None and (r is not None) != want:
        fail(f"{name}: the reference gives {r is not None}, the case is made to give {want}")
    if r is None:
        f.add(KIND_CERT, name, blob(data) + u64(now) + u64(INVALID_CERT) + u64(0) + blob(b"") + blob(b""))
    else:
        f.add(KIND_CERT, name, blob(data) + u64(now) + u64(OK) + u64(r[0]) + blob(r[1]) + blob(r[2]))
    return r


class Host:
    """A libp2p host key: its PublicKey protobuf and its signatures."""

    def __init__(self, typ, rng):
        self.typ = typ
        if typ == KEY_ED25519:
            self.key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(rng.randrange(256) for _ in range(32)))
            data = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            curve = ec.SECP256K1() if typ == KEY_SECP256K1 else ec.SECP256R1()
            self.key = ec.derive_private_key(rng.randrange(1, 1 << 250), curve)
            if typ == KEY_SECP256K1:
                data = self.key.public_key().public_bytes(serialization.Encoding.X962,
                                                          serialization.PublicFormat.CompressedPoint)
            else:
                data = self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo)
        self.proto = bytes([0x08, typ, 0x12, len(data)]) + data

    def sign(self, msg):
        if self.typ == KEY_ED25519:
            return self.key.sign(msg)
        return self.key.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))


def make_cert(rng, cert_key, host, nb, na, critical=False, extra=(), proto=None, host_sig=None, msg_key=None):
    spki_of = (msg_key or cert_key).public_key().public_bytes(serialization.Encoding.DER,
                                                               serialization.PublicFormat.SubjectPublicKeyInfo)
    sig = host_sig if host_sig is not None else host.sign(b"libp2p-tls-handshake:" + spki_of)
    signed_key = der(0x30, der(0x04, proto if proto is not None else host.proto) + der(0x04, sig))
    name = x509.Name([x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, str(rng.randrange(1 << 60)))])
    b = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(cert_key.public_key())
    b = b.serial_number(rng.randrange(1, 1 << 63)).not_valid_before(nb).not_valid_after(na)
    b = b.add_extension(x509.UnrecognizedExtension(LIBP2P_OID, signed_key), critical=critical)
    for oid, value, crit in extra:
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value), critical=crit)
    if isinstance(cert_key, ed25519.Ed25519PrivateKey):
        return b.sign(cert_key, None).public_bytes(serialization.Encoding.DER)
    if isinstance(cert_key, ec.EllipticCurvePrivateKey):
        return b.sign(cert_key, hashes.SHA256(), ecdsa_deterministic=True).public_bytes(serialization.Encoding.DER)
    return b.sign(cert_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def spec_certs(text):
    """(name, certificate, peer ID or None) of the test vectors of tls.md."""
    out = []
    for m in re.finditer(r"### (\d)\. ([^\n]+)\n\n(?:[^\n]+\n\n)?Certificate:\n```\n([0-9a-f]+)\n```\n(?:\nPeerId: `(\w+)`)?", text):
        out.append((f"tls.md/{m.group(1)}", bytes.fromhex(m.group(3)), m.group(4)))
    if len(out) != 4:
        fail(f"tls.md: {len(out)} test vectors")
    return out


def certificates(out, f, rng):
    def rb(n):
        return bytes(rng.randrange(256) for _ in range(n))

    now = int(datetime.datetime(2026, 11, 15, tzinfo=datetime.timezone.utc).timestamp())
    s = f("libp2p-tls.bin")
    for name, data, pid in spec_certs(fetch(out, "tls.md").decode()):
        r = cert_case(s, name, data, now)
        if pid is None:
            if r is not None:
                fail(f"{name}: the invalid certificate passes the checks")
        elif r is None or peer_id(r[2]) != pid:
            fail(f"{name}: the checks do not give the peer ID {pid}")
    g = f("cert-generated.bin")
    utc = datetime.timezone.utc
    nb, na = datetime.datetime(1975, 1, 1, 13, tzinfo=utc), datetime.datetime(4096, 1, 1, 13, tzinfo=utc)

    def p256():
        return ec.derive_private_key(rng.randrange(1, 1 << 250), ec.SECP256R1())

    def ed():
        return ed25519.Ed25519PrivateKey.from_private_bytes(rb(32))

    hosts = [Host(t, rng) for t in (KEY_ED25519, KEY_SECP256K1, KEY_ECDSA)]
    for i in range(36):
        cert_key = p256() if i % 2 == 0 else ed()
        host = hosts[(i // 2) % 3] if i >= 6 else Host((KEY_ED25519, KEY_SECP256K1, KEY_ECDSA)[(i // 2) % 3], rng)
        cert_case(g, f"valid_{i}", make_cert(rng, cert_key, host, nb, na), now, True)
    k, h = p256(), hosts[1]
    t0, t1 = datetime.datetime(2026, 1, 1, tzinfo=utc), datetime.datetime(2027, 1, 1, tzinfo=utc)
    c = make_cert(rng, k, h, t0, t1)
    for name, at, want in (("at_not_before", t0, True), ("at_not_after", t1, True),
                           ("before_not_before", t0 - datetime.timedelta(seconds=1), False),
                           ("after_not_after", t1 + datetime.timedelta(seconds=1), False)):
        cert_case(g, name, c, int(at.timestamp()), want)
    for name, a, b in (("utctime_1950", datetime.datetime(1950, 1, 1, tzinfo=utc), t1),
                       ("generalized_2050", t0, datetime.datetime(2050, 1, 1, tzinfo=utc)),
                       ("generalized_9999", t0, datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=utc)),
                       ("leap_day", datetime.datetime(2024, 2, 29, 12, tzinfo=utc), t1),
                       ("expired_2025", t0 - datetime.timedelta(days=400), datetime.datetime(2025, 12, 31, tzinfo=utc))):
        cert_case(g, name, make_cert(rng, k, h, a, b), now)
    cert_case(g, "critical_libp2p", make_cert(rng, k, h, nb, na, critical=True), now, True)
    cert_case(g, "unknown_noncritical", make_cert(rng, k, h, nb, na, extra=[("1.2.3.4", b"\x05\x00", False)]), now, True)
    cert_case(g, "unknown_critical", make_cert(rng, k, h, nb, na, extra=[("1.2.3.4", b"\x05\x00", True)]), now, False)
    cert_case(g, "keyusage_critical", make_cert(rng, k, h, nb, na, extra=[("2.5.29.15", b"\x03\x02\x07\x80", True)]),
              now, True)
    cert_case(g, "big_extension", make_cert(rng, k, h, nb, na, extra=[("1.2.3.5", der(0x04, rb(1700)), False)]), now, False)
    cert_case(g, "host_signs_other_key", make_cert(rng, k, h, nb, na, msg_key=p256()), now, False)
    cert_case(g, "host_wrong_message", make_cert(rng, k, h, nb, na, host_sig=h.sign(b"libp2p-tls-handshake:")), now, False)
    for typ, data in ((KEY_RSA, rb(70)), (4, rb(32)), (KEY_ED25519, rb(33)), (KEY_SECP256K1, rb(32))):
        proto = bytes([0x08, typ, 0x12, len(data)]) + data
        cert_case(g, f"host_type_{typ}_{len(data)}", make_cert(rng, k, h, nb, na, proto=proto), now, False)
    proto = bytes([0x12, len(h.proto) - 4]) + h.proto[4:] + bytes([0x08, h.typ])
    cert_case(g, "host_fields_reversed", make_cert(rng, k, h, nb, na, proto=proto), now, True)
    cert_case(g, "host_type_twice", make_cert(rng, k, h, nb, na, proto=h.proto + bytes([0x08, h.typ])), now, False)
    hs = hosts[1]
    spki = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    r_s = der_items(der_items(hs.sign(b"libp2p-tls-handshake:" + spki))[0][1])
    r, sv = int.from_bytes(r_s[0][1], "big"), int.from_bytes(r_s[1][1], "big")
    sv = SECP256K1_N - sv

    def dint(v):
        b = v.to_bytes(33, "big").lstrip(b"\0")
        return der(0x02, b"\0" + b if b[0] & 0x80 else b)

    high = der(0x30, dint(r) + dint(sv))
    cert_case(g, "secp256k1_high_s", make_cert(rng, k, hs, nb, na, host_sig=high), now, True)
    good = make_cert(rng, k, h, nb, na)
    bad = bytearray(good)
    bad[-5] ^= 0x01
    cert_case(g, "bad_self_signature", bytes(bad), now, False)
    cert_case(g, "trailing_byte", good + b"\x00", now, False)
    cert_case(g, "truncated", good[:-1], now, False)
    cert_case(g, "empty", b"", now, False)
    cert_case(g, "p384_key", make_cert(rng, ec.derive_private_key(rng.randrange(1, 1 << 250), ec.SECP384R1()), h, nb, na),
              now, False)
    cert_case(g, "rsa_key", make_cert(rng, rsa.generate_private_key(65537, 1024), h, nb, na), now, False)
    cert_case(g, "missing_extension", x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(x509.Name([]))
              .public_key(k.public_key()).serial_number(5).not_valid_before(nb).not_valid_after(na)
              .sign(k, hashes.SHA256(), ecdsa_deterministic=True).public_bytes(serialization.Encoding.DER), now, False)
    for i in range(20):
        cut = bytearray(good)
        cut[rng.randrange(len(cut))] ^= 1 << rng.randrange(8)
        cert_case(g, f"flipped_{i}", bytes(cut), now)



def main(out):
    rng = random.Random(9001)

    def rb(n):
        return bytes(rng.randrange(256) for _ in range(n))

    files = {}

    def f(name):
        return files.setdefault(name, VectorFile())

    dcid = bytes.fromhex("8394c8f03e515708")
    a = appendix_a(fetch(out, "rfc9001.txt").decode())
    client = a["client_key"] + a["client_iv"] + bytes(4) + a["client_hp"]
    server = a["server_key"] + a["server_iv"] + bytes(4) + a["server_hp"]
    if packet_keys(a["client_secret"]) != client or packet_keys(a["server_secret"]) != server:
        fail("rfc 9001: the steps of section 5.1 do not give the keys of A.1")

    # RFC 9001 appendix A.
    r = f("rfc9001.bin")
    initial_case(r, "A.1/initial_keys", dcid, client + server)
    payload = a["client_crypto"] + bytes(1162 - len(a["client_crypto"]))
    seal_case(r, "A.2/seal", client, 2, a["client_header"], payload, a["client_packet"])
    open_case(r, "A.2/open", client, len(a["client_header"]) - 4, NONE, a["client_packet"],
              (OK, 2, a["client_header"], payload))
    seal_case(r, "A.3/seal", server, 1, a["server_header"], a["server_payload"], a["server_packet"])
    open_case(r, "A.3/open", server, len(a["server_header"]) - 2, NONE, a["server_packet"],
              (OK, 1, a["server_header"], a["server_payload"]))
    retry_case(r, "A.4/retry_tag", dcid, a["retry"][:-16], a["retry"][-16:])

    # Generated cases.
    g = f("packet-generated.bin")
    for n in list(range(0, 21)) + [21, 22, 255]:
        initial_case(g, f"initial_keys_{n}", rb(min(n, 20)) if n <= 20 else rb(n))
    for i in range(40):
        initial_case(g, f"initial_keys_random_{i}", rb(rng.randrange(1, 21)))

    def header(long, pn_len, pn, extra):
        if long:
            first = 0xC0 | (rng.randrange(4) << 4) | (pn_len - 1)
            h = bytes([first]) + b"\x00\x00\x00\x01" + bytes([8]) + rb(8) + bytes([8]) + rb(8) + extra
        else:
            first = 0x40 | (rng.randrange(8) << 2) | (pn_len - 1)
            h = bytes([first]) + rb(8) + extra
        return h + (pn & ((1 << (8 * pn_len)) - 1)).to_bytes(pn_len, "big")

    sizes = [0, 1, 2, 3, 4, 5, 15, 16, 17, 31, 32, 33, 100, 1000, 1162, 1200, 1400, 1460, 1484, 1485, 1504, 1505]
    for i in range(240):
        long = i % 2 == 0
        pn_len = 1 + (i // 2) % 4
        pn = rng.randrange(1 << 62) if i % 3 else rng.randrange(1 << (8 * pn_len))
        h = header(long, pn_len, pn, rb(rng.randrange(0, 4)))
        p = rb(sizes[i % len(sizes)] if i < 3 * len(sizes) else rng.randrange(0, 1300))
        keys = rb(16) + rb(12) + bytes(4) + rb(16)
        sealed = seal_case(g, f"seal_{i}", keys, pn, h, p)
        if not sealed:
            continue
        pn_off = len(h) - pn_len
        # The largest packet number received: around pn, so the truncated number decodes back to pn.
        hwin = 1 << (8 * pn_len - 1)
        for j, largest in enumerate((pn - 1, pn - hwin + 1, pn + hwin - 2, pn + 1)):
            if not 0 <= largest < (1 << 62):
                largest = NONE if pn < hwin else pn - 1
            open_case(g, f"open_{i}_{j}", keys, pn_off, largest, sealed)
        bad = bytearray(sealed)
        bad[rng.randrange(len(h), len(bad))] ^= 1 << rng.randrange(8)
        open_case(g, f"open_{i}_flipped", keys, pn_off, pn - 1 if pn else NONE, bytes(bad))
        open_case(g, f"open_{i}_other_key", rb(16) + keys[16:], pn_off, pn - 1 if pn else NONE, sealed)
    # The example of RFC 9000 appendix A.3: largest 0xa82f30ea, a 2-byte truncated 0x9b32.
    keys = rb(16) + rb(12) + bytes(4) + rb(16)
    h = bytes([0x41]) + rb(8) + bytes([0x9B, 0x32])
    sealed = seal_case(g, "seal_rfc9000_a3", keys, 0xA82F9B32, h, rb(40))
    open_case(g, "open_rfc9000_a3", keys, 9, 0xA82F30EA, sealed)
    # Short or malformed packets.
    for n in (0, 1, 19, 20, 21, 25, 26):
        open_case(g, f"open_short_{n}", keys, 1, NONE, rb(n))
    open_case(g, "open_pn_offset_past_end", keys, 40, NONE, rb(40))
    open_case(g, "open_too_long", keys, 9, NONE, rb(HEADER_MAX + SEALED_MAX + 1))
    seal_case(g, "seal_empty_header", keys, 0, b"", rb(20))
    seal_case(g, "seal_long_header", keys, 0, bytes([0x40]) + rb(256), rb(20))
    seal_case(g, "seal_pn_past_header", keys, 0, bytes([0x43]) + rb(2), rb(20))
    seal_case(g, "seal_too_long", keys, 0, bytes([0x40]) + rb(9), rb(SEALED_MAX - 15))
    for i in range(30):
        retry_case(g, f"retry_tag_{i}", rb(rng.randrange(0, 21)), rb(rng.randrange(20, 200)))

    certificates(out, f, rng)

    for name in sorted(files):
        files[name].write(os.path.join(out, name))
        print(f"{name}: {len(files[name].cases)} cases")


if __name__ == "__main__":
    main(sys.argv[1])

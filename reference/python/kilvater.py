"""A second, independent implementation of the Kilvater wire format.

This is a clean-room reimplementation of the parts Kilvater defines itself
(docs/KILVATER.md): the request tag (v1 and v2), the v2 key derivation, the
frame codec and the address encoding. It exists to pin the spec: a cross-compat
test (test_vectors.py) checks it against the same golden vectors the Go
reference is checked against (kilvater/testdata/vectors.json), so the two
implementations are proven to agree byte for byte.

It is deliberately dependency-free (Python standard library only) and does NOT
implement TLS 1.3 or HTTP/2 — those layers are provided by standard libraries in
any real client, and Kilvater adds no cipher of its own (spec §1). It is a
reference for the format, not a production transport.

The replay cache (spec §3, step 3) is stateful server behaviour and is out of
scope here; verify_v1/verify_v2 check structure, the time window, the path and
the MAC (and, for v2, revocation), which is what a second implementation needs
to pin.
"""

import base64
import hashlib
import hmac

MAX_FRAME = 16 << 10  # 16384; a longer frame body is a protocol error
TAG_WINDOW = 120  # seconds a tag's clock may differ from the server's

# Frame types (spec §4).
FRAME_OPEN = 1
FRAME_DATA = 2
FRAME_PAD = 3
FRAME_DGRAM = 4
FRAME_CLOSE = 5

# Networks named in an OPEN body.
NET_TCP = 1
NET_UDP = 2

# Domain-separation labels. The trailing NUL is part of each label.
_MAC_V1 = b"kilvater/1\x00"
_MAC_V2 = b"kilvater/2\x00"
_KID_INFO = b"kilvater/kid\x00"
_KEY_INFO = b"kilvater/key\x00"

_TAG_VERSION_2 = 2
_KEY_ID_SIZE = 8


# --- base64url without padding, as used for the tag cookie value ---

def b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --- HKDF-SHA256 (RFC 5869), used for the v2 key derivation ---

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        # RFC 5869: an absent salt is HashLen zero bytes. Go's crypto/hkdf does
        # the same, so an empty salt here must match a nil salt there.
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


# --- v2 key scheme (spec §7) ---

def key_id_for(master: bytes, subscriber: bytes) -> bytes:
    """keyID = HMAC-SHA256(master, "kilvater/kid\\0" || subscriber)[:8]."""
    return hmac.new(master, _KID_INFO + subscriber, hashlib.sha256).digest()[:_KEY_ID_SIZE]


def derive_key(master: bytes, key_id: bytes) -> bytes:
    """key = HKDF-SHA256(master, "", "kilvater/key\\0" || keyID, 32)."""
    return hkdf_sha256(master, b"", _KEY_INFO + key_id, 32)


# --- the request tag (spec §3) ---

def _ts8(ts: int) -> bytes:
    return ts.to_bytes(8, "big")


def mac_v1(key: bytes, ts8: bytes, nonce: bytes, path: str) -> bytes:
    m = hmac.new(key, _MAC_V1 + ts8 + nonce + path.encode("utf-8"), hashlib.sha256)
    return m.digest()[:16]


def new_tag_v1(key: bytes, path: str, ts: int, nonce: bytes) -> str:
    ts8 = _ts8(ts)
    raw = ts8 + nonce + mac_v1(key, ts8, nonce, path)
    return b64url_nopad(raw)


def mac_v2(key: bytes, key_id: bytes, ts8: bytes, nonce: bytes, path: str) -> bytes:
    m = hmac.new(key, _MAC_V2 + key_id + ts8 + nonce + path.encode("utf-8"), hashlib.sha256)
    return m.digest()[:16]


def new_tag_v2(key_id: bytes, key: bytes, path: str, ts: int, nonce: bytes) -> str:
    ts8 = _ts8(ts)
    raw = bytes([_TAG_VERSION_2]) + key_id + ts8 + nonce + mac_v2(key, key_id, ts8, nonce, path)
    return b64url_nopad(raw)


def _within(ts: int, now: int) -> bool:
    return abs(now - ts) <= TAG_WINDOW


def verify_v1(keys, tag: str, path: str, now: int) -> int:
    """Return the matching key's index, or -1. Constant-time MAC compare."""
    try:
        raw = b64url_decode(tag)
    except Exception:
        return -1
    if len(raw) != 32:
        return -1
    ts8, nonce, got = raw[0:8], raw[8:16], raw[16:32]
    if not _within(int.from_bytes(ts8, "big"), now):
        return -1
    for i, k in enumerate(keys):
        if hmac.compare_digest(mac_v1(k, ts8, nonce, path), got):
            return i
    return -1


def verify_v2(master: bytes, revoked, tag: str, path: str, now: int):
    """Return the accepted key id (hex), or None. `revoked` is a set of id hex."""
    try:
        raw = b64url_decode(tag)
    except Exception:
        return None
    if len(raw) != 1 + _KEY_ID_SIZE + 8 + 8 + 16 or raw[0] != _TAG_VERSION_2:
        return None
    key_id = raw[1:1 + _KEY_ID_SIZE]
    off = 1 + _KEY_ID_SIZE
    ts8, nonce, got = raw[off:off + 8], raw[off + 8:off + 16], raw[off + 16:]
    if not _within(int.from_bytes(ts8, "big"), now):
        return None
    if key_id.hex() in (revoked or set()):
        return None
    key = derive_key(master, key_id)
    if not hmac.compare_digest(mac_v2(key, key_id, ts8, nonce, path), got):
        return None
    return key_id.hex()


# --- frames (spec §4): [type:1][length:3 big-endian][body] ---

def write_frame(typ: int, body: bytes) -> bytes:
    if len(body) > MAX_FRAME:
        raise ValueError("kilvater: frame too long")
    n = len(body)
    return bytes([typ, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]) + body


def read_frame(buf: bytes):
    """Return (type, body, rest). Raises on a short buffer or an over-long frame."""
    if len(buf) < 4:
        raise ValueError("kilvater: short frame header")
    typ = buf[0]
    n = (buf[1] << 16) | (buf[2] << 8) | buf[3]
    if n > MAX_FRAME:
        raise ValueError("kilvater: frame too long")
    if len(buf) < 4 + n:
        raise ValueError("kilvater: short frame body")
    return typ, buf[4:4 + n], buf[4 + n:]


# --- target address (spec §4): [len:1]["host:port"] ---

def append_addr(hostport: str) -> bytes:
    hp = hostport.encode("utf-8")
    if not (1 <= len(hp) <= 255):
        raise ValueError("kilvater: bad address")
    return bytes([len(hp)]) + hp


def parse_addr(buf: bytes):
    """Return (hostport, rest)."""
    if len(buf) < 1 or buf[0] == 0 or len(buf) < 1 + buf[0]:
        raise ValueError("kilvater: bad address")
    n = buf[0]
    return buf[1:1 + n].decode("utf-8"), buf[1 + n:]

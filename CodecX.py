# Extra codecs for multicodec: Base58, XOR, RailFence, ROT5
from __future__ import annotations
from typing import Union
import base64, binascii

from CodecX import BaseCodec, register_codec, add_simple_codec, CodecError

StrOrBytes = Union[str, bytes, bytearray, memoryview]

def _to_bytes(x: StrOrBytes, encoding="utf-8", errors="strict") -> bytes:
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    return str(x).encode(encoding, errors)

def _to_str(b: bytes, encoding="utf-8", errors="strict") -> str:
    return b.decode(encoding, errors)

# ---------------- Base58 ----------------
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {ch: i for i, ch in enumerate(_B58_ALPHABET)}

def _b58encode(b: bytes, alphabet: str = _B58_ALPHABET) -> str:
    if not b:
        return ""
    n = int.from_bytes(b, "big")
    out = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(alphabet[r])
    out = "".join(reversed(out)) or alphabet[0]
    # preserve leading zeros as '1'
    zeros = len(b) - len(b.lstrip(b"\x00"))
    return alphabet[0] * zeros + out

def _b58decode(s: str, alphabet: str = _B58_ALPHABET) -> bytes:
    if not s:
        return b""
    index = {ch: i for i, ch in enumerate(alphabet)}
    n = 0
    for ch in s:
        try:
            n = n * 58 + index[ch]
        except KeyError as e:
            raise CodecError(f"Invalid Base58 character: {ch!r}") from e
    raw = b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")
    zeros = len(s) - len(s.lstrip(alphabet[0]))
    return b"\x00" * zeros + raw

class Base58Codec(BaseCodec):
    name = "base58"
    aliases = ("b58",)
    help = "Base58 (Bitcoin alphabet). Options: alphabet, as_bytes, encoding, errors"

    def encode(self, data: StrOrBytes, **options):
        enc = options.get("encoding", "utf-8")
        errors = options.get("errors", "strict")
        as_bytes = bool(options.get("as_bytes", False))
        alphabet = options.get("alphabet", _B58_ALPHABET)
        s = _b58encode(_to_bytes(data, enc, errors), alphabet)
        return s.encode("ascii") if as_bytes else s

    def decode(self, data: StrOrBytes, **options):
        enc = options.get("encoding", "utf-8")
        errors = options.get("errors", "strict")
        as_bytes = bool(options.get("as_bytes", False))
        alphabet = options.get("alphabet", _B58_ALPHABET)
        s = data.decode("ascii") if isinstance(data, (bytes, bytearray, memoryview)) else str(data)
        out = _b58decode(s, alphabet)
        return out if as_bytes else _to_str(out, enc, errors)

# ---------------- XOR (with wrapping) ----------------
class XorCodec(BaseCodec):
    name = "xor"
    help = "XOR stream with repeating key. Options: key(str|bytes, required), wrap('b64'|'hex'|'none' default='b64'), as_bytes, encoding, errors"

    def _key_bytes(self, key: StrOrBytes | None, encoding: str) -> bytes:
        if key is None:
            raise CodecError("xor requires a key")
        kb = _to_bytes(key, encoding, "strict")
        if not kb:
            raise CodecError("xor key cannot be empty")
        return kb

    def _xor(self, data: bytes, key: bytes) -> bytes:
        k = len(key)
        return bytes(b ^ key[i % k] for i, b in enumerate(data))

    def _wrap(self, b: bytes, wrap: str) -> bytes:
        if wrap == "b64":
            return base64.b64encode(b)
        if wrap == "hex":
            return binascii.hexlify(b)
        if wrap == "none":
            return b
        raise CodecError(f"Unknown wrap: {wrap}")

    def _unwrap(self, b: StrOrBytes, wrap: str) -> bytes:
        if isinstance(b, str):
            b = b.encode("ascii")
        if wrap == "b64":
            return base64.b64decode(b)
        if wrap == "hex":
            return binascii.unhexlify(bytes(b).strip())
        if wrap == "none":
            return bytes(b)
        raise CodecError(f"Unknown wrap: {wrap}")

    def encode(self, data: StrOrBytes, **options):
        enc = options.get("encoding", "utf-8")
        errors = options.get("errors", "strict")
        as_bytes = bool(options.get("as_bytes", False))
        wrap = options.get("wrap", "b64")
        key = self._key_bytes(options.get("key"), enc)
        out = self._xor(_to_bytes(data, enc, errors), key)
        wrapped = self._wrap(out, wrap)
        return wrapped if as_bytes or wrap == "none" else wrapped.decode("ascii")

    def decode(self, data: StrOrBytes, **options):
        enc = options.get("encoding", "utf-8")
        errors = options.get("errors", "strict")
        as_bytes = bool(options.get("as_bytes", False))
        wrap = options.get("wrap", "b64")
        key = self._key_bytes(options.get("key"), enc)
        raw = self._unwrap(data, wrap)
        out = self._xor(raw, key)
        return out if as_bytes else _to_str(out, enc, errors)

# ---------------- Rail Fence cipher ----------------
class RailFenceCodec(BaseCodec):
    name = "railfence"
    aliases = ("zigzag",)
    help = "Rail Fence cipher. Options: rails(int>=2), encoding, errors"

    def _pattern(self, n: int, rails: int) -> list[int]:
        # which rail each character goes to
        r, step = 0, 1
        pat = []
        for _ in range(n):
            pat.append(r)
            if r == 0:
                step = 1
            elif r == rails - 1:
                step = -1
            r += step
        return pat

    def encode(self, data: StrOrBytes, **options):
        s = _to_str(_to_bytes(data, options.get("encoding", "utf-8"), options.get("errors", "strict")))
        rails = int(options.get("rails", 3))
        if rails < 2:
            raise CodecError("rails must be >= 2")
        pat = self._pattern(len(s), rails)
        buckets = [""] * rails
        for ch, r in zip(s, pat):
            buckets[r] += ch
        return "".join(buckets)

    def decode(self, data: StrOrBytes, **options):
        s = _to_str(_to_bytes(data, options.get("encoding", "utf-8"), options.get("errors", "strict")))
        rails = int(options.get("rails", 3))
        if rails < 2:
            raise CodecError("rails must be >= 2")
        pat = self._pattern(len(s), rails)
        # Count how many chars per rail
        counts = [pat.count(r) for r in range(rails)]
        parts = []
        i = 0
        for c in counts:
            parts.append(s[i : i + c])
            i += c
        # Reconstruct by iterating pattern
        idx = [0] * rails
        out = []
        for r in pat:
            out.append(parts[r][idx[r]])
            idx[r] += 1
        return "".join(out)

def _rot5_transform(data: StrOrBytes, **options) -> str:
    s = _to_str(_to_bytes(data, options.get("encoding", "utf-8"), options.get("errors", "strict")))
    out = []
    for ch in s:
        if "0" <= ch <= "9":
            out.append(chr(((ord(ch) - ord("0") + 5) % 10) + ord("0")))
        else:
            out.append(ch)
    return "".join(out)

# Register the extras
register_codec(Base58Codec())
register_codec(XorCodec())
register_codec(RailFenceCodec())
add_simple_codec("rot5", _rot5_transform, _rot5_transform, aliases=("r5",), help="ROT5 (digits 0-9)")

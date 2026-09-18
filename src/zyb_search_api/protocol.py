"""Pure-Python implementation of the native Zyb anti-spam protocol.

This module is a clean-room translation of the algorithms used by
libbaseutil.so.  It does not load the APK, execute ARM code, or require Java.
"""

from __future__ import annotations

import hashlib
import secrets
import string


PREFIX = "8&%d*"
DES_KEY = b"@fG2SuLA"
KEY_SALT = "@#AIjd83#@6B"
SIGNATURE_CHARS_MD5 = "0f3c509eef614432e414ce9d37f00c80"
RANDOM_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits

# The tables are zero-based, exactly as stored in libbaseutil.so.  PC2[35]
# intentionally contains 46 rather than the standard DES value 47.
IP = (57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7,56,48,40,32,24,16,8,0,58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6)
IP_INV = (39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25,32,0,40,8,48,16,56,24)
E = (31,0,1,2,3,4,3,4,5,6,7,8,7,8,9,10,11,12,11,12,13,14,15,16,15,16,17,18,19,20,19,20,21,22,23,24,23,24,25,26,27,28,27,28,29,30,31,0)
P = (15,6,19,20,28,11,27,16,0,14,22,25,4,17,30,9,1,7,23,13,31,26,2,8,18,12,29,5,21,10,3,24)
PC1 = (56,48,40,32,24,16,8,0,57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,60,52,44,36,28,20,12,4,27,19,11,3)
PC2 = (13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,25,7,15,6,26,19,12,1,40,51,30,36,46,54,29,39,50,44,32,46,43,48,38,55,33,52,45,41,49,35,28,31)
SHIFTS = (1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1)
SBOXES = (
((14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7),(0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8),(4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0),(15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13)),
((15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10),(3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5),(0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15),(13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9)),
((10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8),(13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1),(13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7),(1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12)),
((7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15),(13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9),(10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4),(3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14)),
((2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9),(14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6),(4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14),(11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3)),
((12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11),(10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8),(9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6),(4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13)),
((4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1),(13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6),(1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2),(6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12)),
((13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7),(1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2),(7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8),(2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11)),
)


class ProtocolError(ValueError):
    pass


def _md5(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> bit) & 1 for byte in data for bit in range(8)]


def _bits_to_bytes(bits: list[int]) -> bytes:
    return bytes(sum(bit << index for index, bit in enumerate(bits[offset:offset + 8]))
                 for offset in range(0, len(bits), 8))


def _subkeys(key: bytes) -> list[list[int]]:
    if len(key) != 8:
        raise ProtocolError("DES key must contain exactly 8 bytes")
    source = _bytes_to_bits(key)
    selected = [source[index] for index in PC1]
    left, right = selected[:28], selected[28:]
    result = []
    for shift in SHIFTS:
        left = left[shift:] + left[:shift]
        right = right[shift:] + right[:shift]
        joined = left + right
        result.append([joined[index] for index in PC2])
    return result


def _crypt_block(block: bytes, key: bytes, decrypt: bool = False) -> bytes:
    permuted = [_bytes_to_bits(block)[index] for index in IP]
    left, right = permuted[:32], permuted[32:]
    keys = _subkeys(key)
    if decrypt:
        keys.reverse()
    for subkey in keys:
        expanded = [right[index] for index in E]
        mixed = [a ^ b for a, b in zip(expanded, subkey)]
        substituted: list[int] = []
        for box_index in range(8):
            chunk = mixed[box_index * 6:(box_index + 1) * 6]
            row = chunk[0] * 2 + chunk[5]
            column = chunk[1] * 8 + chunk[2] * 4 + chunk[3] * 2 + chunk[4]
            value = SBOXES[box_index][row][column]
            substituted.extend((value >> bit) & 1 for bit in (3, 2, 1, 0))
        transformed = [substituted[index] for index in P]
        left, right = right, [a ^ b for a, b in zip(left, transformed)]
    swapped = right + left
    return _bits_to_bytes([swapped[index] for index in IP_INV])


def des_encrypt(clear: bytes, key: bytes) -> bytes:
    padding = 8 - len(clear) % 8
    # The native code uses zero fill plus a final byte containing the padding
    # length.  For one-byte padding this is identical to PKCS#7.
    padded = clear + bytes(padding - 1) + bytes([padding])
    return b"".join(_crypt_block(padded[offset:offset + 8], key)
                    for offset in range(0, len(padded), 8))


def des_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % 8:
        raise ProtocolError("invalid DES ciphertext length")
    clear = b"".join(_crypt_block(ciphertext[offset:offset + 8], key, True)
                     for offset in range(0, len(ciphertext), 8))
    padding = clear[-1]
    native_padding = bytes(padding - 1) + bytes([padding])
    if padding < 1 or padding > 8 or clear[-padding:] != native_padding:
        raise ProtocolError("invalid DES padding")
    return clear[:-padding]


def _reverse_byte(value: int) -> int:
    return int(f"{value:08b}"[::-1], 2)


def encode_wire(ciphertext: bytes) -> str:
    return "".join(f"{_reverse_byte(byte) >> 4:02x}{_reverse_byte(byte) & 15:02x}"
                   for byte in ciphertext)


def decode_wire(value: str) -> bytes:
    if len(value) % 4:
        raise ProtocolError("invalid encoded ciphertext length")
    try:
        encoded = bytes((int(value[offset:offset + 2], 16) << 4) |
                        int(value[offset + 2:offset + 4], 16)
                        for offset in range(0, len(value), 4))
    except ValueError as exc:
        raise ProtocolError("encoded ciphertext is not hexadecimal") from exc
    return bytes(_reverse_byte(byte) for byte in encoded)


def create_sign_a(cuid: str, challenge: str | None = None) -> tuple[str, str]:
    challenge = challenge or "".join(secrets.choice(RANDOM_ALPHABET) for _ in range(10))
    if len(challenge) != 10 or any(char not in RANDOM_ALPHABET for char in challenge):
        raise ProtocolError("challenge must be 10 ASCII letters or digits")
    clear = f"{PREFIX}##{challenge}##{SIGNATURE_CHARS_MD5}##{cuid}".encode("utf-8")
    return encode_wire(des_encrypt(clear, DES_KEY)), challenge


def accept_sign_b(cuid: str, sign_a: str, sign_b: str) -> str:
    try:
        clear_a = des_decrypt(decode_wire(sign_a), DES_KEY).decode("utf-8")
    except (UnicodeDecodeError, ProtocolError) as exc:
        raise ProtocolError("invalid signA") from exc
    parts = clear_a.split("##")
    if (len(parts) != 4 or parts[0] != PREFIX or len(parts[1]) != 10
            or parts[2] != SIGNATURE_CHARS_MD5 or parts[3] != cuid):
        raise ProtocolError("signA integrity check failed")
    challenge = parts[1]
    key = (challenge[:5] + "#G4").encode("ascii")
    try:
        clear_b = des_decrypt(decode_wire(sign_b), key).decode("utf-8")
    except (UnicodeDecodeError, ProtocolError) as exc:
        raise ProtocolError("invalid signB") from exc
    response_parts = clear_b.split("##")
    if len(response_parts) != 2 or response_parts[0] != challenge or len(response_parts[1]) != 10:
        raise ProtocolError("signB integrity check failed")
    return response_parts[1]


def request_sign(payload_base64: str, session_token: str) -> str:
    return _md5(f"{PREFIX}[{_md5(session_token)}]@{payload_base64}")


def response_key(version_code: str, session_token: str) -> str:
    token_marker = f"[{session_token}]@"
    reversed_token_md5 = list(_md5(token_marker))
    # The ARM loop performs exactly 15 swaps.  The two centre characters of
    # this 32-character digest therefore keep their original order.
    for index in range(15):
        reversed_token_md5[index], reversed_token_md5[-1 - index] = (
            reversed_token_md5[-1 - index], reversed_token_md5[index]
        )
    combined = _md5(KEY_SALT) + _md5(version_code) + "".join(reversed_token_md5)
    chars = list(combined)
    for index in range(3):
        chars[index], chars[-1 - index] = chars[-1 - index], chars[index]
    shuffled = "".join(chars)
    result = list(shuffled + _md5(shuffled))
    for index in range(60):
        result[index], result[-1 - index] = result[-1 - index], result[index]
    return "".join(result)

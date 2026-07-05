#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure-Python port of B's internal/zte/security.go (line-by-line fork).

Provides the ZTE security envelope primitives:
  - decode_security_params  (AES-CBC decrypt of ZTE_Security_Params hex)
  - decode_security_json    (decode_security_params + json parse)
  - encode_security_params  (AES-CBC encrypt -> uppercase hex)
  - encode_vdi_password     (AES-ECB encrypt -> base64)
  - decode_connect_string   (AES-ECB decrypt of hex -> str)

AES is implemented in pure Python (both encrypt and decrypt) so this module
is self-contained and independently unit-testable, mirroring Go's crypto/aes.
"""

import base64
import json

# ---------------------------------------------------------------------------
# AES constants (FIPS-197)
# ---------------------------------------------------------------------------

_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

AES_BLOCK_SIZE = 16


def _gmul(a, b):
    """Multiply two bytes in GF(2^8) with the AES reduction polynomial."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _key_expansion(key):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
    for i in range(nk, 4 * (nr + 1)):
        temp = words[i - 1][:]
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(nr + 1):
        rk = [0] * 16
        for col in range(4):
            for row in range(4):
                rk[row + 4 * col] = words[4 * r + col][row]
        round_keys.append(rk)
    return round_keys, nr


def _add_round_key(state, rk):
    for i in range(16):
        state[i] ^= rk[i]


def _sub_bytes(state):
    for i in range(16):
        state[i] = _SBOX[state[i]]


def _inv_sub_bytes(state):
    for i in range(16):
        state[i] = _INV_SBOX[state[i]]


def _shift_rows(state):
    # state is column-major: state[row + 4*col]
    s = state[:]
    for row in range(1, 4):
        for col in range(4):
            state[row + 4 * col] = s[row + 4 * ((col + row) % 4)]


def _inv_shift_rows(state):
    s = state[:]
    for row in range(1, 4):
        for col in range(4):
            state[row + 4 * col] = s[row + 4 * ((col - row) % 4)]


def _mix_columns(state):
    for col in range(4):
        i = 4 * col
        s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i] = _gmul(s0, 2) ^ _gmul(s1, 3) ^ s2 ^ s3
        state[i + 1] = s0 ^ _gmul(s1, 2) ^ _gmul(s2, 3) ^ s3
        state[i + 2] = s0 ^ s1 ^ _gmul(s2, 2) ^ _gmul(s3, 3)
        state[i + 3] = _gmul(s0, 3) ^ s1 ^ s2 ^ _gmul(s3, 2)


def _inv_mix_columns(state):
    for col in range(4):
        i = 4 * col
        s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i] = _gmul(s0, 14) ^ _gmul(s1, 11) ^ _gmul(s2, 13) ^ _gmul(s3, 9)
        state[i + 1] = _gmul(s0, 9) ^ _gmul(s1, 14) ^ _gmul(s2, 11) ^ _gmul(s3, 13)
        state[i + 2] = _gmul(s0, 13) ^ _gmul(s1, 9) ^ _gmul(s2, 14) ^ _gmul(s3, 11)
        state[i + 3] = _gmul(s0, 11) ^ _gmul(s1, 13) ^ _gmul(s2, 9) ^ _gmul(s3, 14)


def aes_encrypt_block(block, round_keys, nr):
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    state = list(block)
    _add_round_key(state, round_keys[0])
    for r in range(1, nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[nr])
    return bytes(state)


def aes_decrypt_block(block, round_keys, nr):
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    state = list(block)
    _add_round_key(state, round_keys[nr])
    for r in range(nr - 1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[r])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return bytes(state)


def aes_ecb_encrypt(data, key):
    if len(data) % AES_BLOCK_SIZE != 0:
        raise ValueError("ECB data must be block-aligned")
    round_keys, nr = _key_expansion(key)
    out = bytearray()
    for off in range(0, len(data), AES_BLOCK_SIZE):
        out += aes_encrypt_block(data[off:off + AES_BLOCK_SIZE], round_keys, nr)
    return bytes(out)


def aes_ecb_decrypt(data, key):
    if len(data) % AES_BLOCK_SIZE != 0:
        raise ValueError("ECB data must be block-aligned")
    round_keys, nr = _key_expansion(key)
    out = bytearray()
    for off in range(0, len(data), AES_BLOCK_SIZE):
        out += aes_decrypt_block(data[off:off + AES_BLOCK_SIZE], round_keys, nr)
    return bytes(out)


def aes_cbc_encrypt(data, key, iv):
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")
    if len(data) % AES_BLOCK_SIZE != 0:
        raise ValueError("CBC data must be block-aligned")
    round_keys, nr = _key_expansion(key)
    previous = iv
    out = bytearray()
    for off in range(0, len(data), AES_BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(data[off:off + AES_BLOCK_SIZE], previous))
        enc = aes_encrypt_block(block, round_keys, nr)
        out += enc
        previous = enc
    return bytes(out)


def aes_cbc_decrypt(data, key, iv):
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")
    if len(data) % AES_BLOCK_SIZE != 0:
        raise ValueError("CBC data must be block-aligned")
    round_keys, nr = _key_expansion(key)
    previous = iv
    out = bytearray()
    for off in range(0, len(data), AES_BLOCK_SIZE):
        block = data[off:off + AES_BLOCK_SIZE]
        plain = aes_decrypt_block(block, round_keys, nr)
        out += bytes(a ^ b for a, b in zip(plain, previous))
        previous = block
    return bytes(out)


def pkcs7_pad(data, block_size=AES_BLOCK_SIZE):
    pad = block_size - len(data) % block_size
    return data + bytes([pad]) * pad


def pkcs7_unpad(data, block_size=AES_BLOCK_SIZE):
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("invalid pkcs7 data length: %d" % len(data))
    pad = data[-1]
    if pad == 0 or pad > block_size or pad > len(data):
        raise ValueError("invalid pkcs7 padding: %d" % pad)
    if any(b != pad for b in data[-pad:]):
        raise ValueError("invalid pkcs7 padding bytes")
    return data[:-pad]


# ---------------------------------------------------------------------------
# ZTE security constants (from B security.go)
# ---------------------------------------------------------------------------

SECURITY_KEY = b"56Acf4c3498fD4c5a0B1fb26947e2daB"
SECURITY_IV = b"3498fD4c5a0B1fbA"
VDI_KEY = b"3fec8a54-7e49-48"


# ---------------------------------------------------------------------------
# Port of B security.go functions
# ---------------------------------------------------------------------------

def decode_security_params(body):
    """Port of DecodeSecurityParams: unwrap ZTE_Security_Params envelope, AES-CBC decrypt."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    try:
        env = json.loads(body)
    except Exception as exc:
        raise ValueError("parse security envelope: %s" % exc)
    params = env.get("ZTE_Security_Params", "") if isinstance(env, dict) else ""
    if params == "":
        return body
    try:
        ciphertext = bytes.fromhex(params)
    except Exception as exc:
        raise ValueError("decode security params hex: %s" % exc)
    if len(ciphertext) == 0 or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("invalid security params length: %d" % len(ciphertext))
    plain = aes_cbc_decrypt(ciphertext, SECURITY_KEY, SECURITY_IV)
    plain = pkcs7_unpad(plain, AES_BLOCK_SIZE)
    return plain


def decode_security_json(body):
    """Port of DecodeSecurityJSON: decode_security_params + json parse."""
    plain = decode_security_params(body)
    try:
        return json.loads(plain)
    except Exception as exc:
        raise ValueError("parse decoded security json: %s (body: %s)" % (exc, plain.decode("utf-8", "replace")))


def encode_security_params(plaintext):
    """Port of EncodeSecurityParams: AES-CBC encrypt -> uppercase hex."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    padded = pkcs7_pad(plaintext, AES_BLOCK_SIZE)
    ciphertext = aes_cbc_encrypt(padded, SECURITY_KEY, SECURITY_IV)
    return ciphertext.hex().upper()


def encode_vdi_password(password):
    """Port of EncodeVDIPassword: AES-ECB encrypt (block-by-block) -> base64."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    plain = pkcs7_pad(password, AES_BLOCK_SIZE)
    ciphertext = aes_ecb_encrypt(plain, VDI_KEY)
    return base64.b64encode(ciphertext).decode("ascii")


def decode_connect_string(connect_str):
    """Port of DecodeConnectString: hex decode -> AES-ECB decrypt -> pkcs7 unpad -> str."""
    try:
        ciphertext = bytes.fromhex(connect_str)
    except Exception as exc:
        raise ValueError("decode connectStr hex: %s" % exc)
    if len(ciphertext) == 0 or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("invalid connectStr length: %d" % len(ciphertext))
    plain = aes_ecb_decrypt(ciphertext, VDI_KEY)
    plain = pkcs7_unpad(plain, AES_BLOCK_SIZE)
    return plain.decode("utf-8", "replace")

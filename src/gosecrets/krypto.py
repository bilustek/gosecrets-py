"""AES-256-GCM encryption/decryption compatible with Go gosecrets."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_SIZE = 32  # AES-256


def decrypt(hex_ciphertext: bytes, hex_key: str) -> bytes:
    """Decrypt hex-encoded ciphertext using AES-256-GCM with hex-encoded key.

    The ciphertext format (after hex-decoding) is: nonce (12 bytes) || ciphertext+tag.
    This matches the Go gosecrets format.
    """
    key = bytes.fromhex(hex_key)
    if len(key) != _KEY_SIZE:
        msg = f'key must be {_KEY_SIZE} bytes, got {len(key)}'
        raise ValueError(msg)

    raw = bytes.fromhex(hex_ciphertext.decode('ascii'))

    nonce_size = 12  # AES-GCM standard nonce size
    if len(raw) < nonce_size:
        msg = 'ciphertext too short'
        raise ValueError(msg)

    nonce = raw[:nonce_size]
    ciphertext = raw[nonce_size:]

    gcm = AESGCM(key)
    return gcm.decrypt(nonce, ciphertext, None)

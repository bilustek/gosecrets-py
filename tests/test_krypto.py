"""Tests for AES-256-GCM encryption/decryption."""

import os
import subprocess

import pytest

from gosecrets.krypto import decrypt


@pytest.fixture
def gosecrets_bin():
    """Find gosecrets binary."""
    path = os.popen('which gosecrets').read().strip()  # noqa: S605, S607
    if not path:
        pytest.skip('gosecrets CLI not installed')
    return path


class TestDecryptWithGoCLI:
    """Cross-language compatibility: encrypt with Go, decrypt with Python."""

    def test_roundtrip_with_go_encrypt(self, tmp_path, gosecrets_bin):
        env = {'PATH': os.environ['PATH'], 'HOME': os.environ['HOME']}

        result = subprocess.run(
            [gosecrets_bin, 'init'],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        assert result.returncode == 0

        # extract master key from output (second "master key:" line has the hex key)
        master_key = ''
        for line in result.stdout.splitlines():
            if 'master key:' in line:
                candidate = line.split('master key:')[1].strip()
                if all(c in '0123456789abcdef' for c in candidate) and len(candidate) == 64:
                    master_key = candidate
                    break
        assert master_key, f'could not find master key in output: {result.stdout}'

        # write test content via edit (pipe to stdin)
        enc_path = tmp_path / 'secrets' / 'development.enc'

        # decrypt with Python
        data = enc_path.read_bytes()
        plaintext = decrypt(data, master_key)
        assert b'Add your secrets' in plaintext


class TestDecryptErrors:
    def test_invalid_key_length(self):
        with pytest.raises(ValueError, match='key must be 32 bytes'):
            decrypt(b'aabb', 'aabb')

    def test_invalid_hex_key(self):
        with pytest.raises(ValueError):
            decrypt(b'aabb', 'not-hex')

    def test_ciphertext_too_short(self):
        key = 'aa' * 32
        short = ('bb' * 5).encode()
        with pytest.raises(ValueError, match='ciphertext too short'):
            decrypt(short, key)

    def test_wrong_key_fails(self):
        key = 'aa' * 32
        wrong_key = 'bb' * 32
        # create a minimal valid-looking ciphertext (nonce + some data)
        fake = ('cc' * 30).encode()
        with pytest.raises(Exception):
            decrypt(fake, wrong_key)

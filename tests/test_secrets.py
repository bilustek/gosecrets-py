"""Tests for Secrets class and load function."""

import os
import subprocess

import pytest

from gosecrets import Secrets, load


@pytest.fixture
def gosecrets_bin():
    """Find gosecrets binary."""
    path = os.popen('which gosecrets').read().strip()  # noqa: S605, S607
    if not path:
        pytest.skip('gosecrets CLI not installed')
    return path


def _init_store(tmp_path, gosecrets_bin, env='development', content=None):
    """Initialize a gosecrets store and optionally write content."""
    base_env = {'PATH': os.environ['PATH'], 'HOME': os.environ['HOME']}

    args = [gosecrets_bin, 'init']
    if env != 'development':
        args.extend(['--env', env])

    result = subprocess.run(args, cwd=tmp_path, capture_output=True, text=True, env=base_env, check=False)
    assert result.returncode == 0

    master_key = ''
    for line in result.stdout.splitlines():
        if 'master key:' in line:
            candidate = line.split('master key:')[1].strip()
            if all(c in '0123456789abcdef' for c in candidate) and len(candidate) == 64:
                master_key = candidate
                break

    if content is not None:
        # encrypt content using the Go-compatible format
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key_bytes = bytes.fromhex(master_key)
        gcm = AESGCM(key_bytes)
        nonce = os.urandom(12)
        ciphertext = gcm.encrypt(nonce, content.encode(), None)
        raw = nonce + ciphertext
        hex_encoded = raw.hex().encode()

        enc_file = f'{env}.enc'
        (tmp_path / 'secrets' / enc_file).write_bytes(hex_encoded)

    return master_key


class TestLoad:
    def test_load_default(self, tmp_path, gosecrets_bin, monkeypatch):
        master_key = _init_store(tmp_path, gosecrets_bin, content='api_key: test-123\n')
        monkeypatch.setenv('GOSECRETS_MASTER_KEY', master_key)

        secrets = load(root=str(tmp_path))
        assert secrets.string('api_key') == 'test-123'

    def test_load_with_env(self, tmp_path, gosecrets_bin, monkeypatch):
        master_key = _init_store(tmp_path, gosecrets_bin, env='production', content='api_key: prod-456\n')
        monkeypatch.setenv('GOSECRETS_MASTER_KEY', master_key)

        secrets = load(root=str(tmp_path), env='production')
        assert secrets.string('api_key') == 'prod-456'

    def test_load_env_from_env_var(self, tmp_path, gosecrets_bin, monkeypatch):
        master_key = _init_store(tmp_path, gosecrets_bin, env='staging', content='api_key: staging-789\n')
        monkeypatch.setenv('GOSECRETS_MASTER_KEY', master_key)
        monkeypatch.setenv('GOSECRETS_ENV', 'staging')

        secrets = load(root=str(tmp_path))
        assert secrets.string('api_key') == 'staging-789'

    def test_load_env_specific_key(self, tmp_path, gosecrets_bin, monkeypatch):
        master_key = _init_store(tmp_path, gosecrets_bin, env='production', content='api_key: prod-key\n')
        monkeypatch.setenv('GOSECRETS_PRODUCTION_KEY', master_key)

        secrets = load(root=str(tmp_path), env='production')
        assert secrets.string('api_key') == 'prod-key'

    def test_load_key_from_file(self, tmp_path, gosecrets_bin, monkeypatch):
        master_key = _init_store(tmp_path, gosecrets_bin, content='api_key: from-file\n')
        # don't set env var — should read from secrets/development.key
        monkeypatch.delenv('GOSECRETS_MASTER_KEY', raising=False)

        secrets = load(root=str(tmp_path))
        assert secrets.string('api_key') == 'from-file'

    def test_load_missing_key_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv('GOSECRETS_MASTER_KEY', raising=False)
        monkeypatch.delenv('GOSECRETS_DEVELOPMENT_KEY', raising=False)
        (tmp_path / 'secrets').mkdir()
        (tmp_path / 'secrets' / 'development.enc').write_bytes(b'deadbeef')

        with pytest.raises(FileNotFoundError, match='cannot read master key'):
            load(root=str(tmp_path))


class TestSecrets:
    @pytest.fixture
    def secrets(self):
        return Secrets(
            {
                'api_key': 'sk-123',
                'database': {'host': 'localhost', 'port': 5432, 'password': 'secret'},
                'enabled': True,
                'pi': 3.14,
                'count': 42,
            }
        )

    def test_get(self, secrets):
        assert secrets.get('api_key') == 'sk-123'
        assert secrets.get('database.host') == 'localhost'
        assert secrets.get('database.port') == 5432
        assert secrets.get('nonexistent') is None
        assert secrets.get('database.nonexistent') is None

    def test_string(self, secrets):
        assert secrets.string('api_key') == 'sk-123'
        assert secrets.string('database.port') == '5432'
        assert secrets.string('nonexistent') == ''
        assert secrets.string('nonexistent', 'default') == 'default'

    def test_integer(self, secrets):
        assert secrets.integer('count') == 42
        assert secrets.integer('database.port') == 5432
        assert secrets.integer('nonexistent') == 0
        assert secrets.integer('nonexistent', 99) == 99
        assert secrets.integer('api_key', 0) == 0

    def test_floating(self, secrets):
        assert secrets.floating('pi') == 3.14
        assert secrets.floating('count') == 42.0
        assert secrets.floating('nonexistent') == 0.0
        assert secrets.floating('nonexistent', 1.5) == 1.5

    def test_boolean(self, secrets):
        assert secrets.boolean('enabled') is True
        assert secrets.boolean('nonexistent') is False
        assert secrets.boolean('nonexistent', True) is True
        assert secrets.boolean('api_key') is False

    def test_mapping(self, secrets):
        db = secrets.mapping('database')
        assert db is not None
        assert db['host'] == 'localhost'
        assert secrets.mapping('nonexistent') is None
        assert secrets.mapping('nonexistent', {'default': True}) == {'default': True}
        assert secrets.mapping('api_key') is None

    def test_has(self, secrets):
        assert secrets.has('api_key') is True
        assert secrets.has('database.host') is True
        assert secrets.has('nonexistent') is False

    def test_keys(self, secrets):
        keys = secrets.keys()
        assert 'api_key' in keys
        assert 'database.host' in keys
        assert 'database.port' in keys
        assert 'database.password' in keys
        assert 'enabled' in keys
        assert 'database' not in keys  # non-leaf

    def test_all(self, secrets):
        data = secrets.all()
        assert 'api_key' in data
        assert 'database' in data

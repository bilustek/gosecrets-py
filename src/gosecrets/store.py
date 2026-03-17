"""Credential store: reads encrypted files and resolves master keys."""

from __future__ import annotations

import os
from pathlib import Path

from gosecrets.krypto import decrypt

ENV_MASTER_KEY = 'GOSECRETS_MASTER_KEY'
ENV_ENV = 'GOSECRETS_ENV'
DEFAULT_ENV = 'development'
DEFAULT_DIR = 'secrets'


class Store:
    """Manages encrypted credential files and master keys."""

    def __init__(self, *, root: str = '.', env: str = DEFAULT_ENV) -> None:
        self._dir = Path(root) / DEFAULT_DIR
        self._env = env
        self._credentials_file = f'{env}.enc'
        self._key_file = f'{env}.key'

    def master_key(self) -> str:
        """Resolve the master key.

        Priority:
        1. GOSECRETS_MASTER_KEY environment variable
        2. GOSECRETS_<ENV>_KEY environment variable
        3. Key file on disk
        """
        key = os.environ.get(ENV_MASTER_KEY, '').strip()
        if key:
            return key

        env_var = f'GOSECRETS_{self._env.upper()}_KEY'
        key = os.environ.get(env_var, '').strip()
        if key:
            return key

        key_path = self._dir / self._key_file
        try:
            return key_path.read_text().strip()
        except FileNotFoundError:
            msg = f'cannot read master key (set {ENV_MASTER_KEY} or {env_var}, or create {key_path})'
            raise FileNotFoundError(msg) from None

    def read_credentials(self, master_key: str) -> bytes:
        """Decrypt and return the raw credentials content."""
        cred_path = self._dir / self._credentials_file
        try:
            data = cred_path.read_bytes()
        except FileNotFoundError:
            msg = f'cannot read credentials file: {cred_path}'
            raise FileNotFoundError(msg) from None

        return decrypt(data, master_key)

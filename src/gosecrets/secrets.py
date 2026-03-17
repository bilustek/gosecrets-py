"""Secrets: load and access encrypted credentials with dot notation."""

from __future__ import annotations

import os
from typing import Any

import yaml

from gosecrets.store import DEFAULT_ENV, ENV_ENV, Store


def load(*, root: str = '.', env: str | None = None) -> Secrets:
    """Load and decrypt credentials.

    Environment resolution order: env parameter > GOSECRETS_ENV > "development".

    Usage::

        secrets = load()
        secrets = load(root="/app", env="production")
    """
    if env is None:
        env = os.environ.get(ENV_ENV, '').strip() or DEFAULT_ENV

    store = Store(root=root, env=env)
    master_key = store.master_key()
    plaintext = store.read_credentials(master_key)

    data = yaml.safe_load(plaintext)
    if data is None:
        data = {}

    return Secrets(data)


class Secrets:
    """Holds decrypted credentials with dot-notation access."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def get(self, key: str) -> Any:
        """Retrieve a value using dot notation (e.g. "database.password").

        Returns None if the key doesn't exist.
        """
        parts = key.split('.')
        current: Any = self._data

        for part in parts:
            if not isinstance(current, dict):
                return None
            current = current.get(part)
            if current is None:
                return None

        return current

    def string(self, key: str, fallback: str = '') -> str:
        """Retrieve a string value using dot notation."""
        value = self.get(key)
        if value is None:
            return fallback
        return str(value)

    def integer(self, key: str, fallback: int = 0) -> int:
        """Retrieve an integer value using dot notation."""
        value = self.get(key)
        if value is None:
            return fallback
        try:
            return int(value)
        except (ValueError, TypeError):
            return fallback

    def floating(self, key: str, fallback: float = 0.0) -> float:
        """Retrieve a float value using dot notation."""
        value = self.get(key)
        if value is None:
            return fallback
        try:
            return float(value)
        except (ValueError, TypeError):
            return fallback

    def boolean(self, key: str, fallback: bool = False) -> bool:  # noqa: FBT001, FBT002
        """Retrieve a boolean value using dot notation."""
        value = self.get(key)
        if value is None:
            return fallback
        if isinstance(value, bool):
            return value
        return fallback

    def mapping(self, key: str, fallback: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Retrieve a nested dict using dot notation."""
        value = self.get(key)
        if value is None:
            return fallback
        if isinstance(value, dict):
            return value
        return fallback

    def has(self, key: str) -> bool:
        """Check if a key exists in the credentials."""
        return self.get(key) is not None

    def keys(self) -> list[str]:
        """Return all dot-notation key paths."""
        result: list[str] = []
        _collect_keys(self._data, '', result)
        return result

    def all(self) -> dict[str, Any]:
        """Return the entire credentials dict."""
        return self._data


def _collect_keys(data: dict[str, Any], prefix: str, result: list[str]) -> None:
    for key, value in data.items():
        full = f'{prefix}.{key}' if prefix else key
        if isinstance(value, dict):
            _collect_keys(value, full, result)
        else:
            result.append(full)

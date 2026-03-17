# gosecrets

[![PyPI version](https://img.shields.io/pypi/v/gosecrets.svg)](https://pypi.org/project/gosecrets/)
[![Python versions](https://img.shields.io/pypi/pyversions/gosecrets.svg)](https://pypi.org/project/gosecrets/)
[![License](https://img.shields.io/pypi/l/gosecrets.svg)](https://github.com/bilustek/gosecrets-py/blob/main/LICENSE)

Python client for [gosecrets](https://github.com/bilustek/gosecrets) — encrypted
credentials management. Read secrets encrypted by the Go CLI directly from your
Python projects.

CLI Tool via Homebrew:

```bash
brew tap bilustek/tap
brew install gosecrets
```

or via `go install`:

```bash
go install github.com/bilustek/gosecrets/cmd/gosecrets@latest
```

---

## Installation

```bash
pip install gosecrets
```

---

## Quick Start

First, create your encrypted credentials using the [gosecrets CLI](https://github.com/bilustek/gosecrets):

```bash
gosecrets init                  # for development environment
gosecrets init --env production # or production environment

gosecrets edit                  # edit development environment
gosecrets edit --env production # or edit production environment
```

Then read them in Python:

```python
from gosecrets import load

secrets = load()
print(secrets.string("database.password"))
print(secrets.integer("database.port"))
```

---

## Usage

### Loading Credentials

```python
from gosecrets import load

# default: reads secrets/development.enc
secrets = load()

# specify environment
secrets = load(env="production")

# specify root directory
secrets = load(root="/app", env="production")
```

Environment resolution order:

1. `env` parameter
2. `GOSECRETS_ENV` environment variable
3. `"development"` (default)

Master key resolution order:

1. `GOSECRETS_MASTER_KEY` environment variable
2. `GOSECRETS_<ENV>_KEY` environment variable (e.g. `GOSECRETS_PRODUCTION_KEY`)
3. Key file on disk (`secrets/<env>.key`)

### Accessing Values

All accessors support **dot notation** for nested keys:

```python
secrets.get("database.password")       # Any — raw value or None
secrets.string("api_key")              # str — "" if missing
secrets.string("api_key", "default")   # str — with fallback
secrets.integer("database.port")       # int — 0 if missing
secrets.integer("port", 5432)          # int — with fallback
secrets.floating("rate")               # float — 0.0 if missing
secrets.boolean("debug")               # bool — False if missing
secrets.mapping("database")            # dict | None
secrets.has("api_key")                 # bool
secrets.keys()                         # list[str] — all dot-notation paths
secrets.all()                          # dict — entire credentials
```

---

## Compatibility

This package reads credentials encrypted by the [gosecrets CLI](https://github.com/bilustek/gosecrets)
(AES-256-GCM). It is fully compatible with credentials created by the Go library.

---

## Contributor(s)

- [Uğur "vigo" Özyılmazel](https://github.com/vigo) - Creator, maintainer

---

## Contribute

All PR’s are welcome!

1. `fork` (https://github.com/bilustek/gosecrets-py/fork)
1. Create your `branch` (`git checkout -b my-feature`)
1. `commit` yours (`git commit -am 'add some functionality'`)
1. `push` your `branch` (`git push origin my-feature`)
1. Then create a new **Pull Request**!

---

## License

This project is licensed under MIT

---

This project is intended to be a safe, welcoming space for collaboration, and
contributors are expected to adhere to the [code of conduct][coc].

[coc]: https://github.com/bilustek/gosecrets-py/blob/main/CODE_OF_CONDUCT.md

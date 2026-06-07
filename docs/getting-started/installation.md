# Installation

## What you need

- Python 3.11 or later
- A copy of the target `ntds.dit` file and either its `SYSTEM` registry hive or the raw boot key

NTDSWolf is pure Python with no system library dependencies — the cryptographic primitives come from `pycryptodome` and `dpapi-ng`, both of which ship binary wheels.

## Install with uv

```bash
uv tool install git+https://github.com/StrongWind1/NTDSWolf
```

## Install from source

```bash
git clone https://github.com/StrongWind1/NTDSWolf.git
cd NTDSWolf
uv sync
```

## Verify installation

```bash
ntdswolf --version
```

## Run checks

```bash
make check    # lint + typecheck + tests
make docs     # build documentation
```

Or individually:

```bash
uv run ruff check            # linter (all rules enabled)
uv run ruff format --check   # formatter
uv run ty check              # type checker (strictest settings)
uv run pytest                # test suite
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `dissect.database` | ESE database parsing, NTDS object model, schema |
| `dissect.regf` | SYSTEM registry hive parsing for boot key extraction |
| `dpapi-ng` | Offline MS-GKDI / DPAPI-NG decryption for LAPS v2 |
| `pycryptodome` | AES, DES, RC4, MD4, HMAC, PBKDF2 |
| `typing-extensions` | `@override` backport for Python 3.11 |
| `typer` | Command-line interface |
| `rich` | Progress bars and colored output |

## Disclaimer

NTDSWolf is intended for authorized digital forensics, penetration testing, and security auditing only. You must have explicit permission to access the data you process with it.

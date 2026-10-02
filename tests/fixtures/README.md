# Test fixtures

Nothing here is synthetic unless it says so, and nothing here is a private key.

## `lockfiles/`

One demo project (`pyproject.toml`: `requests==2.34.2`, `typer==0.27.2`) locked on
2026-10-02 by the real tools, unmodified:

| File | Written by |
|---|---|
| `uv.lock` | `uv lock` (uv 0.12.22) |
| `pylock.toml` | `uv export --format pylock.toml` |
| `requirements-hashes.txt` | `uv export --format requirements-txt` |
| `poetry.lock` | `poetry lock` (Poetry 2.5.1, lock-version 2.1) |
| `requirements.txt` | by hand: `fastapi==0.142.2`, `requests==2.34.2` (the README example) |

## `pypi/`

Real PyPI responses recorded on 2026-10-02 by `scripts/grabar-fixtures.py`, which runs
attest-lint itself over the lockfiles above through a recording transport, so the
fixtures are exactly the requests the tool makes. `MANIFEST.json` maps each URL to its
file and HTTP status.

- `simple/<project>.json.gz`: the JSON simple index (PEP 691). Only the keys
  attest-lint reads are kept (`filename`, `hashes`, `provenance`, `upload-time`,
  `yanked`); their values are untouched. `core-metadata` and the rest are dropped to
  keep the repository small.
- `integrity/<project>/<version>/<filename>.json.gz`: provenance objects from the
  Integrity API, complete. The two of `requests 2.34.2` are verified offline in the
  tests against the Sigstore trust root bundled with `sigstore`.

## `revision/`

The lockfiles of the adversarial review of 2026-10-02, unmodified: `uvp/` (uv 0.12.22:
`uv.lock`, `pylock.toml`, `requirements.txt` with git, URL, editable and extras), `poe/`
(Poetry, lock-version 2.1) and `req/` (a requirements file with every pip oddity:
glued short options, `-c`, `--pre`, `${VAR}`, a trailing `-i`, `--config-settings`).

Synthetic histories (publisher changes, backports, pre-releases, hash mismatches) are
built in memory by `tests/fabrica.py`; their attestations are empty and never verified.

To refresh: `python scripts/grabar-fixtures.py` (the only thing that uses the network).

# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: SemVer.

## [0.1.0] — unreleased

First release.

### Changed after the adversarial review (2026-10-02)
- **AT-001 compares release with release**: it fires only when no file of the pinned
  release is attested. New **AT-005** (warning) when the release is attested but none of
  the files the lockfile pins is (a project that attests only its sdist, a lock that pins
  the wheel), with a truthful message instead of a false regression.
- **AT-002 compares files of the same kind**: sdist with sdist, wheel with a wheel of the
  same tags (or any wheel). Comparing an sdist with a wheel built by another workflow
  invented publisher changes.
- **`--verify` exits 2** when any attestation could not be verified: a CI with
  `verify: true` no longer goes green without having verified anything.
- **Mirrors and private indexes**: with sha256 values in the lockfile, entries resolved
  from another index, registry, URL or archive are checked against PyPI by digest in all
  four formats (SRC-002 if the file is not PyPI's); without sha256 they are SRC-001. A
  `uv.lock` against Artifactory no longer turns everything into SRC-001 and exit 2.
- Locked files are matched with PyPI's by sha256 first and then by parsed filename, not
  by literal name (uv writes `zope_interface-…` in pylock for PyPI's `zope.interface-…`).
- Local versions (`torch==2.1.0+cpu`) are SRC-001 without any request: PyPI rejects them.
- Requirements files: pip 26's own preprocessing (continuations, then comments, then
  `${VAR}`; an unset variable is LOCK-001 naming it), short options written together
  (`-rsub.txt`, `-ihttps://…`, `-e./x`), constraints files (`-c`) not checked,
  `--no-index` is SRC-003, index options apply to the whole file as in pip, and
  `>=2,==2.8.0` counts as pinned.
- Cache: an entry whose body no longer parses is fetched again instead of failing for the
  whole TTL. Redirects are followed only to `https://pypi.org`. After the first
  connection failure no further requests are attempted in the run.
- `--verify-max-files N` (default 10, 0 = all): wheels for the running platform first.
- TOML lockfile names are validated (`canonicalize_name(..., validate=True)`); SRC-001
  messages include the version; yanked releases count and are marked; the message for a
  release with only `.egg`/`.exe` files no longer says "no files".
- Release workflow runs tests, ruff and mypy before building; `attest-build-provenance`
  v4.2.2. CI runs on pushes to `main` and on pull requests, not twice. `packaging>=23.2`.

### Added
- `attest-lint` CLI with text, JSON and SARIF output. Options: `--type`, `--format
  text|json|sarif`, `--strict`, `--window N`, `--allow NAME[==VERSION]`, `--allowlist
  FILE`, `--verify`, `--offline`, `--cache-dir`, `--cache-ttl`, `--no-cache`,
  `--no-color`. Without arguments it looks for `pylock.toml`, `uv.lock`, `poetry.lock`
  or `requirements.txt` in the working directory.
- Rules AT-001 (attestation regression, error), AT-002 (publisher changed, warning;
  error with `--strict`), AT-003 (never attested, info), AT-004 (attestation does not
  verify, `--verify` only) and AT-005 (attested release, unattested locked files), plus LOCK-001/002, SRC-001/002/003 and NET-001. Every rule
  cites PEP 740, PEP 691/700, PEP 751, the PyPI Integrity API or pip's documentation;
  `SPEC.md` quotes each source literally.
- History ordered by upload date, not version number; pre-releases excluded from the
  history of a final release; only the files the lockfile pins are considered.
- Lockfile readers: `pylock.toml` (PEP 751, lock-version 1.x), `uv.lock` (version 1),
  `poetry.lock` (lock-version 1.x and 2.x), pip requirements files (`==`/`===`, `--hash`,
  continuations, comments, `-r`, `-c`). Unknown versions are rejected, not half-read.
- PyPI client: identifiable User-Agent, ≤ 10 requests/s, retries on 429/5xx honouring
  `Retry-After`, on-disk cache (indexes 1 h, provenance 7 days), `--offline`.
- Cryptographic verification with `pypi-attestations` (optional extra `verify`), against
  the lockfile's sha256 when it pins one.
- Exit codes: `0` no errors, `1` errors (or warnings with `--strict`), `2` the tool could
  not do its job. Never a traceback.
- GitHub Action (composite, installs from its own code), CI workflow (Linux, macOS,
  Windows × Python 3.11–3.14) and release workflow (build, provenance attestation,
  GitHub Release, PyPI via Trusted Publishing once enabled). Every third-party action
  pinned by SHA with its exact version.
- Tests that never touch the network: real PyPI responses recorded on 2026-10-02
  (`scripts/grabar-fixtures.py`), real lockfiles written by uv 0.12.22 and Poetry 2.5.1,
  and real attestations of `requests 2.34.2` verified offline.

# attest-lint

<img alt="EasyxLab tool" src="https://raw.githubusercontent.com/easybytehub/attest-lint/main/.github/badge-tool.svg">

A "no-downgrade" check for the Python supply chain. attest-lint reads your lockfile and
warns when a pinned dependency **stopped shipping [PEP 740] attestations** on PyPI, or
when its **Trusted Publisher changed**, compared with that package's own history.

```console
$ cat requirements.txt
fastapi==0.142.2
requests==2.34.2

$ attest-lint requirements.txt --verify
attest-lint · 1 lockfile(s) · 2 package(s) checked against PyPI · window: all releases

ERROR        AT-001 [requirements.txt:1] fastapi 0.142.2: Attestation regression: earlier releases were attested, this one is not
             PyPI serves no PEP 740 attestation for any file of fastapi 0.142.2, but 53 of the 313 earlier final releases have one. Last attested: 0.128.0 (2025-12-27); 54 release(s) without attestation since then, this one included.
             A regression is not proof of compromise: a new CI pipeline, a manual upload or a pre-release built elsewhere look the same from the index. Check the project's release notes or workflow before trusting this release, or allowlist it.
             citation: PEP 740, “JSON-based Simple API” (the per-file `provenance` key); PyPI Integrity API, GET /integrity/<project>/<version>/<filename>/provenance

1 error · 0 warnings · 0 info · 0 undetermined
```

(Real output, 2026-10-02. `requests 2.34.2` is attested by `psf/requests`, the same
publisher as 2.34.1, and both of its files verify.)

## Why

Since 2024 PyPI can serve, for every uploaded file, a signed statement of which
repository and workflow published it. That is only useful if someone notices when it
**goes missing**: a release published with a stolen API token instead of the project's
CI looks exactly like an unattested release. Measured by EasyxLab on 2026-10-02:
FastAPI published 53 attested releases (November 2024 to 0.128.0 in December 2025) and
none since; Typer, the same. Nothing in the Python tooling flags this today. pnpm has
[`trustPolicy: no-downgrade`][pnpm] for npm. We found nothing equivalent in pip or uv
(as of 2026-10-02): uv can *upload* attestations, but nothing checks them on install.

## What a finding means — and what it does not

**A regression is a signal to review, not proof of compromise.** Projects stop attesting
because they move CI, rename a workflow, upload a release by hand or build a pre-release
elsewhere. attest-lint tells you what changed in the index; only the project can tell
you why. Equally, **no findings does not mean your dependencies are safe**: a
compromised CI pipeline publishes perfectly attested malware, and most packages have
never attested anything (AT-003), so there is nothing to compare against.

## Rules

| Rule | Severity | Fires when |
|---|---|---|
| AT-001 | error | no file of the pinned release is attested, but earlier releases are (regression) |
| AT-002 | warning (error with `--strict`) | the publisher (repository, workflow, environment) differs from the last attested release, comparing files of the same kind |
| AT-003 | info | the package has never published attestations |
| AT-004 | error (`--verify` only) | an attestation does not verify; *undetermined* (exit 2) when it could not be checked |
| AT-005 | warning | the release is attested, but none of the files your lockfile pins is |
| LOCK-001 | undetermined, exit 2 | the lockfile (or a line of it) cannot be read reliably |
| LOCK-002 | info | an entry is not pinned to an exact version |
| SRC-001 | info | an entry cannot be checked against PyPI (git, path, local version `+cpu`, another index without sha256, 404) |
| SRC-002 | warning | PyPI has no such release, or the locked files/hashes do not match PyPI's |
| SRC-003 | info | a requirements file uses another index (`-i`, `--extra-index-url`, `-f`, `--no-index`) |
| NET-001 | undetermined, exit 2 | PyPI data could not be retrieved |

Every finding cites its source; [`SPEC.md`](SPEC.md) quotes each one literally.

How the history is read:

- **By upload date, not version number.** A 1.2.9 backport uploaded after 2.0 comes from
  the pipeline the project had *then*. pnpm made the same choice.
- **Pre-releases do not count** as history for a final release. pnpm does the same since
  v10.24.0, “so a trusted prerelease cannot block a stable release that lacks trust
  evidence”.
- **Yanked releases count.** They are still in the index and still say which pipeline
  the project had; a finding marks them as `yanked`.
- **Release against release** for AT-001: a release is attested if any of its files is,
  the pinned one and the earlier ones alike. If the release is attested but the files
  your lockfile pins are not (a project that attests only its sdist, a lock that pins
  the wheel), that is AT-005, not a regression.
- **File against file of the same kind** for AT-002: an sdist with an sdist, a wheel with
  a wheel of the same tags (or, failing that, any wheel). Projects often build the sdist
  and the wheels in different workflows. The publisher identity is the `publisher`
  object minus `claims` (per-run data), and AT-002 fires only when the two files share
  no identity, because PEP 740 lets the index add bundles from third parties.

## Install

```bash
pip install attest-lint            # once published on PyPI
pip install "attest-lint[verify]"  # adds --verify (pypi-attestations + sigstore)
```

Until then, from a GitHub release or `pip install git+https://github.com/easybytehub/attest-lint`.
Python 3.11 or newer. The only required dependency is `packaging`.

## Usage

```bash
attest-lint                      # first of pylock.toml, uv.lock, poetry.lock, requirements.txt here
attest-lint uv.lock --strict
attest-lint requirements.txt --format sarif > attest-lint.sarif
attest-lint poetry.lock --window 10 --allow typer --allowlist reviewed.txt
attest-lint pylock.toml --verify
attest-lint uv.lock --offline    # cache only, never the network
```

| Option | Meaning |
|---|---|
| `--type pylock\|uv\|poetry\|requirements` | force the format (default: by file name) |
| `--format text\|json\|sarif` | output format (default `text`) |
| `--strict` | AT-002 becomes an error; warnings exit 1 |
| `--window N` | AT-001 looks only at the N final releases before the pinned one (default 0 = all) |
| `--allow NAME[==VERSION]` | stop reporting AT-001/002/003/005 for a package or one release; repeatable |
| `--allowlist FILE` | the same, one entry per line, `#` for comments |
| `--verify` | verify attestations with [`pypi-attestations`][pa] (AT-004) |
| `--verify-max-files N` | verify at most N files per release, wheels for this platform first (default 10, 0 = all) |
| `--offline` | read only the cache; a missing entry is NET-001, never "no attestation" |
| `--cache-dir DIR`, `--cache-ttl SECONDS`, `--no-cache` | the on-disk cache (default TTL 3600 s for project indexes) |

Exit codes: **0** no errors; **1** errors (or warnings with `--strict`); **2** the tool
could not do its job: an unreadable lockfile, PyPI data missing, an attestation that
`--verify` could not check, `--verify` without `pypi-attestations`, an internal error,
or a lockfile with nothing pinned to check exits 2 (a `requirements.txt` with only
`>=` ranges, for instance: a green run that checked nothing would be misleading). It
never prints a traceback.

Lockfiles: `pylock.toml` ([PEP 751]) `lock-version` 1.x; `uv.lock` `version = 1`;
`poetry.lock` `lock-version` 1.x and 2.x. `uv.lock` and `poetry.lock` have no public
specification: any other version is rejected (LOCK-001) instead of being read half-way.
Requirements files are preprocessed as pip 26 does it (line continuations, then
comments, then `${VAR}` from the environment; an unset variable is LOCK-001), with
`==`/`===` pins, `--hash`, `-r` (followed) and short options written together
(`-rfile.txt`). Constraints files (`-c`) are not checked: they install nothing.

**Mirrors and private indexes.** An Artifactory or devpi that mirrors PyPI serves the
same files with the same sha256. When the lockfile pins sha256 values, the entry is
checked against PyPI like any other, whatever index it was resolved from, and SRC-002
says so if the file is not PyPI's. Without a sha256 there is no way to match it, and the
entry is skipped (SRC-001). The rule is the same in all four formats.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
  - uses: easybytehub/attest-lint@1715eef2eba95e81f6bebae192792b34e8b38b1b  # v0.1.0
    with:
      lockfiles: uv.lock
      fail: "false"          # let the SARIF upload run, then decide
  - uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2  # v4.38.2
    if: always()             # upload the report even if a previous step failed
    with:
      sarif_file: attest-lint.sarif
```

Inputs: `lockfiles` (one per line), `format` (default `sarif`), `strict`, `fail`,
`window`, `allowlist`, `verify`, `output`, `python-version`. The action installs
attest-lint from its own code, so the version you pin is the code that runs.

## Network behaviour

Two PyPI endpoints, nothing else (plus Sigstore's trust root with `--verify`):

- `GET https://pypi.org/simple/<project>/` with `Accept: application/vnd.pypi.simple.v1+json`
  ([PEP 691]): one request gives the whole history and, per file, its `provenance` URL.
- `GET https://pypi.org/integrity/<project>/<version>/<filename>/provenance`
  ([Integrity API][int]): two per attested package to compare publishers (AT-002), and
  one per verified file with `--verify` (at most `--verify-max-files` per release).

A `User-Agent` of `attest-lint/<version> (+https://github.com/easybytehub/attest-lint)`,
at most ~10 requests per second, retries only on 429/5xx honouring `Retry-After`,
redirects followed only to `https://pypi.org`, and no further attempts after the first
connection failure of a run. A disk cache keeps project indexes 1 hour and provenance
objects 7 days; a cached entry that no longer parses is fetched again. Set
`ATTEST_LINT_CACHE_DIR` or `--cache-dir` to move it.

## Limitations

- **PyPI only.** Packages that cannot be matched with PyPI are reported and skipped.
- **One pair of files per release for AT-002**: the comparison costs two requests, not
  one per file. Different publishers for different wheels of the same release would go
  unnoticed.
- **Partially attested releases** (some files attested, some not) count as attested;
  AT-005 tells you when the unattested ones are the ones you pin.
- **Without `--verify`, attest-lint trusts what the index says.** With it, the digest is
  your lockfile's sha256 when it has one, otherwise PyPI's — the finding says which.
- `--verify --offline` uses the Sigstore trust root bundled with `sigstore`, which ages.
- Environment markers are ignored: every pinned entry is checked, whatever the platform.

## Roadmap

npm (`package-lock.json`, `pnpm-lock.yaml`) is out of scope for 0.1. Also under
consideration: a time-based cutoff like pnpm's `trustPolicyIgnoreAfter`, and comparing
the publisher of every file instead of one pair per release.

## Licence

Apache-2.0. Made by EasyxLab, the research lab of EasyByte Hub S. Coop. Mad.

[PEP 740]: https://peps.python.org/pep-0740/
[PEP 691]: https://peps.python.org/pep-0691/
[PEP 751]: https://peps.python.org/pep-0751/
[int]: https://docs.pypi.org/api/integrity/
[pa]: https://github.com/pypi/pypi-attestations
[pnpm]: https://pnpm.io/supply-chain-security

---

EasyxLab · a research lab by [EasyByte](https://easybyte.es)

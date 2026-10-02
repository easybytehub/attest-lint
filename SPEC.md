# attest-lint — rule specification

Every rule cites the sentence it rests on, copied literally from the source (downloaded
with `curl` and searched with `grep`, not summarised), with its URL and access date.
A test (`tests/test_catalogo.py`) checks that this file and the rule catalogue in
`src/attest_lint/catalogo.py` list the same rules with the same severities.

Severities: **error** (exit 1), **warning** (exit 1 only with `--strict`), **info**,
**undetermined** (the tool could not look: `NET-001`, `LOCK-001` and AT-004 undetermined
with `--verify` exit 2, so a run that could not do what it was asked never ends green).

## Sources

| Source | Status | URL | Accessed |
|---|---|---|---|
| PEP 740 — Index support for digital attestations | Final (resolution 17-Jul-2024) | https://peps.python.org/pep-0740/ (text: `python/peps` `peps/pep-0740.rst`) | 2026-10-02 |
| PEP 691 — JSON-based Simple API for Python Package Indexes | Final | https://peps.python.org/pep-0691/ | 2026-10-02 |
| PEP 700 — Additional Fields for the Simple API | Final | https://peps.python.org/pep-0700/ | 2026-10-02 |
| PEP 751 — pylock.toml | Final | https://peps.python.org/pep-0751/ | 2026-10-02 |
| PyPI Integrity API | live docs | https://docs.pypi.org/api/integrity/ (source: `pypi/warehouse` `docs/user/api/integrity.md`) | 2026-10-02 |
| PyPI docs, Attestations: Introduction | live docs | https://docs.pypi.org/attestations/ | 2026-10-02 |
| pypi-attestations 0.0.30 | library | https://github.com/pypi/pypi-attestations | 2026-10-02 |
| pip, Requirements File Format | live docs | https://pip.pypa.io/en/stable/reference/requirements-file-format/ | 2026-10-02 |
| pip 26, `pip/_internal/req/req_file.py` | implementation | `preprocess`, `join_lines`, `ignore_comments`, `expand_env_variables` | 2026-10-02 |
| PyPI upload validation | implementation | `pypi/warehouse` `warehouse/forklift/metadata.py` | 2026-10-02 |
| pnpm, `trustPolicy` | docs | https://pnpm.io/supply-chain-security (`settings/dependency-resolution.md`) | 2026-10-02 |

**What the index actually serves (observed 2026-10-02).** The JSON simple index answers
with `"api-version": "1.4"` and every file carries `provenance` (a URL or `null`). The
provenance objects of `fastapi 0.128.0` and `requests 2.34.2` have a `publisher` with
`kind`, `repository`, `workflow` and `environment`, and **no `claims` key**, although
PEP 740 says the publisher “must include at minimum: […] A ``claims`` key”. The Integrity API
example shows `"claims": null`. attest-lint therefore treats `claims` as optional and
excludes it from the publisher identity either way.

## Attestation rules

### AT-001

Attestation regression: earlier releases were attested, this one is not.
Severity: **error**. Configurable: `--window N` (look only at the N releases uploaded
before the pinned one; default all) and `--allow` / `--allowlist`.

> When an uploaded file has one or more attestations, the index **MAY** include a
> ``provenance`` key in the ``file`` dictionary for that file.
>
> The value of the ``provenance`` key **SHALL** be either a JSON string or ``null``. If
> ``provenance`` is not ``null``, it **SHALL** be a URL to the associated provenance file.

PEP 740, “JSON-based Simple API”. Accessed 2026-10-02.

> Route: `GET /integrity/<project>/<version>/<filename>/provenance` […]
> `404 Not Found` - file has no provenance

PyPI Integrity API. Accessed 2026-10-02.

How it is applied: **release against release**. A release counts as attested when at
least one of its files has a non-null `provenance`, for the pinned release and for the
earlier ones alike. (When the release is attested but the files the lockfile pins are
not, that is AT-005, not AT-001.) Yanked releases count: they are still served by the
index and still show which pipeline the project had; the finding marks them. Releases are ordered by the
earliest `upload-time` of their files (PEP 700: “the time the file was uploaded to the
index”), not by version number (pnpm's `trustPolicy` documents the same choice: “Trust checks are
based solely on publish date, not semver.”). When the pinned release is final,
pre-releases are left out of its history, as pnpm does since v10.24.0: “prerelease
versions are ignored when evaluating trust evidence for a non-prerelease install, so a
trusted prerelease cannot block a stable release that lacks trust evidence” (pnpm docs,
`settings/dependency-resolution.md`, accessed 2026-10-02). **A regression is not proof of
compromise**: a new CI
pipeline, a manual upload or a pre-release built elsewhere look the same from the index.

### AT-002

Publisher changed since the last attested release.
Severity: **warning** (error with `--strict`). Honours the allowlist.

> ``attestation_bundles`` is a **required** JSON array, containing one or more "bundles"
> of attestations. Each bundle corresponds to a signing identity (such as a Trusted
> Publishing identity), and contains one or more attestation objects.

PEP 740, “Provenance objects”. Accessed 2026-10-02.

> "publisher": { "claims": null, "environment": "", "kind": "GitHub", "repository":
> "pypa/sampleproject", "workflow": "release.yml" }

PyPI Integrity API, example JSON response. Accessed 2026-10-02.

How it is applied: the identity of a bundle is its `publisher` object minus `claims`
(per-run context such as ref or sha); `repository` is compared case-insensitively and a
null `environment` equals an empty one. **File against file of the same kind**: one
attested file of the pinned release (preferably one the lockfile pins) is compared with
an attested file of the last attested release uploaded before it that has the same wheel
tags, or failing that the same type (sdist with sdist, wheel with wheel). Projects often
build the sdist and the wheels in different workflows; comparing across kinds would
invent a publisher change. If there is no file of the same type, nothing is compared.
It fires only when the two provenance objects share **no** identity, because PEP 740
also says:

> the index **MAY** choose to support attestations from sources other than the file's
> uploader, such as third-party auditors or the index itself.

PEP 740, “Changes to provenance objects”. Accessed 2026-10-02.

### AT-003

The package has never published attestations.
Severity: **info**.

> These signatures bind each release distribution (such as an individual sdist or wheel)
> to a strong cryptographic digest of its contents, allowing both PyPI and downstream
> users to verify that a particular package was attested to by a particular identity
> (such as a GitHub Actions workflow).

PyPI docs, “Attestations: Introduction”. Accessed 2026-10-02.

How it is applied: no file of any release on PyPI has a non-null `provenance` (PEP 740
key, quoted under AT-001). Nothing to compare against, so it is context, not a problem.

### AT-004

Attestation does not verify (only with `--verify`).
Severity: **error**; **undetermined** when it cannot be checked (a publisher kind the
installed `pypi-attestations` does not know, or the Sigstore trust root cannot be
refreshed).

> Verifying an attestation object against a distribution file requires verification of
> each of the following: […] ``envelope.statement`` is a valid in-toto v1 Statement, with
> a subject and digest that **MUST** match the distribution's filename and contents.

PEP 740, “Attestation verification”. Accessed 2026-10-02.

> Verify against an existing Python distribution. […] On failure, raises an appropriate
> subclass of `AttestationError`.

pypi-attestations 0.0.30, `Attestation.verify` docstring. Accessed 2026-10-02.

How it is applied: every attestation of every bundle of each relevant file is verified
with `Attestation.verify(bundle.publisher, Distribution(name, digest))`. The digest is
the sha256 from the lockfile when it pins one (the attestation must cover what you
install); otherwise PyPI's own sha256, and the finding says so. `--offline` verifies
against the trust root bundled with `sigstore` without refreshing it.

### AT-005

Attested release, but the locked files carry no attestation.
Severity: **warning**. Honours the allowlist.

> When an uploaded file has one or more attestations, the index **MAY** include a
> ``provenance`` key in the ``file`` dictionary for that file.

PEP 740, “JSON-based Simple API”. Accessed 2026-10-02.

> These signatures bind each release distribution (such as an individual sdist or wheel)
> to a strong cryptographic digest of its contents

PyPI docs, “Attestations: Introduction”. Accessed 2026-10-02.

How it is applied: attestations are per file. When some files of the pinned release are
attested but none of the files the lockfile pins by name and sha256 is (a project that
attests only its sdist, a `pip lock` that pins only the wheel), what gets installed
cannot be tied to a publisher. It is how the project publishes, not a regression, so it
is a warning and not AT-001.

## Lockfile and index rules

### LOCK-001

The lockfile cannot be read. Severity: **undetermined**; exit 2.

> A lock file MUST be named :file:`pylock.toml` or match the regular expression
> ``r"^pylock\.([^.]+)\.toml$"`` if a name for the lock file is desired or if multiple
> lock files exist.

> ``lock-version`` […] This PEP specifies the initial version -- and only valid value
> until future updates to the standard change it -- as ``"1.0"``.

PEP 751. Accessed 2026-10-02.

`uv.lock` and `poetry.lock` are tool formats without a public specification. attest-lint
reads `uv.lock` `version = 1` (checked against a lockfile written by uv 0.12.22) and
`poetry.lock` `lock-version` 1.x (files under `[metadata.files]`) and 2.x (files per
package; checked against Poetry 2.5.1). Any other version is LOCK-001 instead of a
partial read. A requirements line that is not a valid requirement is LOCK-001 too.

### LOCK-002

Not pinned to an exact version: not checked. Severity: **info**.

> ``packages.version`` […] The version SHOULD be specified when the version is known to
> be stable

PEP 751. Accessed 2026-10-02. In requirements files only a single `==` (without `*`)
or `===` specifier pins a release.

### SRC-001

Not installed from PyPI: not checked. Severity: **info**.

> ``packages.index`` […] The base URL for the package index from
> :ref:`packaging:simple-repository-api` where the sdist and/or wheels were found (e.g.
> ``https://pypi.org/simple/``).

PEP 751. Accessed 2026-10-02. Applied to pylock `vcs`/`directory` entries and local
paths; uv `git`/`path`/`directory` sources; Poetry `git`/`directory`/`file` sources;
requirement URLs, paths and `-e`; projects PyPI does not know (404); and **local
versions**, which never reach PyPI's network check:

> The use of local versions in '{metadata.version}' is not allowed.

`pypi/warehouse`, `warehouse/forklift/metadata.py` (upload validation). Accessed
2026-10-02.

**Other indexes and mirrors** (pylock `index`, `archive` or file URLs on another host;
uv `registry` or `url` sources; Poetry `legacy` or `url` sources; requirements under a
non-PyPI `--index-url` or `--no-index`): when the lockfile pins sha256 values, the entry
is checked against PyPI like any other, because a mirror serves PyPI's files with PyPI's
digests, and SRC-002 reports any file that is not PyPI's. Without a sha256 there is
nothing to match, and the entry is SRC-001. The rule is the same in all four formats.

### SRC-002

The pinned release or locked files do not match PyPI. Severity: **warning**.

> ``files``: A list of dictionaries, each one representing an individual file. […]
> ``hashes``: A dictionary mapping a hash name to a hex encoded digest of the file.

PEP 691. Accessed 2026-10-02. Fires when PyPI has no file for the pinned version (after
one cache-bypassing refetch), when a locked filename is not on PyPI, when its locked
sha256 differs from PyPI's, or when no `--hash` matches any file.

### SRC-003

Custom package index: results describe PyPI. Severity: **info**.

> Requirements files only supports certain pip install options, which are listed below.

pip, Requirements File Format, “Supported options”. Accessed 2026-10-02. Fires on
`--extra-index-url`, `-f`/`--find-links`, `--no-index` and on `-i`/`--index-url` other
than PyPI, written apart or together (`-ihttps://…`): pip may install from there, but
attest-lint only knows PyPI's history. As in pip, index options apply to the whole file
and its `-r` includes, wherever they appear.

Requirements files are preprocessed with pip 26's own steps and regular expressions
(`preprocess`: `join_lines`, then `ignore_comments`, then `expand_env_variables`):
“A line ending in an unescaped `\` is treated as a line continuation”, and “Comments are
stripped _after_ line continuations are processed”, so a comment ending in `\` swallows
the next line, as in pip. Environment variables:

> You have to use the POSIX format for variable names including brackets around the
> uppercase name as shown in this example: `${API_TOKEN}`.

pip, Requirements File Format, “Using environment variables”. Accessed 2026-10-02. An
unset variable leaves the line unresolvable: LOCK-001 with the variable's name.
Constraints files (`-c`) are not checked: they install nothing.

### NET-001

PyPI data could not be retrieved. Severity: **undetermined**; exit 2.

> * `403 Forbidden` - access is temporarily disabled by the PyPI administrators
> * `404 Not Found` - file has no provenance
> * `406 Not Acceptable` - `Accept:` header not recognized

PyPI Integrity API, “Status codes”. Accessed 2026-10-02. Fires on network errors,
HTTP errors other than 404 after two retries (429/5xx, honouring `Retry-After`), a body
that is not the expected JSON, a provenance URL outside `https://pypi.org`, a provenance
the index announces but that returns 404, and a cache miss with `--offline`. Never
reported as “no attestation”.

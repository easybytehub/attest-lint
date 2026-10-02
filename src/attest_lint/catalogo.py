"""El catálogo de reglas: un sitio, y sólo uno, donde vive cada cita.

`SPEC.md` describe las mismas reglas con la frase literal de la fuente y la fecha de
consulta, y un test comprueba que ambos listados coinciden. Lo que ve el usuario va en
inglés.
"""

from __future__ import annotations

from dataclasses import dataclass

from attest_lint.hallazgos import Hallazgo, Severidad

E, A, INF, INC = Severidad.ERROR, Severidad.AVISO, Severidad.INFO, Severidad.INCOMPLETO

URL_PEP740 = "https://peps.python.org/pep-0740/"
URL_PEP691 = "https://peps.python.org/pep-0691/"
URL_PEP751 = "https://peps.python.org/pep-0751/"
URL_INTEGRITY = "https://docs.pypi.org/api/integrity/"
URL_ATTESTATIONS = "https://docs.pypi.org/attestations/"
URL_PYPI_ATTESTATIONS = "https://github.com/pypi/pypi-attestations"

PEP740_SIMPLE = "PEP 740, “JSON-based Simple API” (the per-file `provenance` key)"
PEP740_BUNDLE = "PEP 740, “Provenance objects” (`attestation_bundles[].publisher`)"
PEP740_VERIFY = "PEP 740, “Attestation verification”"
INTEGRITY = "PyPI Integrity API, GET /integrity/<project>/<version>/<filename>/provenance"
ATTESTATIONS = "PyPI docs, “Attestations: Introduction”"
PEP691_FILES = "PEP 691, JSON Simple API (`files[].filename`, `files[].hashes`)"
PEP751 = "PEP 751, pylock.toml"
LOCKFILES = "PEP 751 (pylock.toml); uv.lock; poetry.lock; pip requirements file format"


@dataclass(frozen=True)
class Regla:
    id: str
    severidad: Severidad
    titulo: str
    norma: str
    url: str

    def hallazgo(
        self,
        detalle: str,
        *,
        fichero: str = "",
        linea: int = 0,
        paquete: str = "",
        severidad: Severidad | None = None,
    ) -> Hallazgo:
        return Hallazgo(
            regla=self.id,
            severidad=severidad or self.severidad,
            titulo=self.titulo,
            detalle=detalle,
            norma=self.norma,
            fichero=fichero,
            linea=linea,
            paquete=paquete,
            url=self.url,
        )


_REGLAS = (
    # --- Las cuatro reglas de atestación ------------------------------------------------
    Regla(
        "AT-001",
        E,
        "Attestation regression: earlier releases were attested, this one is not",
        f"{PEP740_SIMPLE}; {INTEGRITY}",
        URL_PEP740,
    ),
    Regla(
        "AT-002",
        A,
        "Publisher changed since the last attested release",
        f"{PEP740_BUNDLE}; {INTEGRITY}",
        URL_PEP740,
    ),
    Regla(
        "AT-003",
        INF,
        "The package has never published attestations",
        f"{PEP740_SIMPLE}; {ATTESTATIONS}",
        URL_ATTESTATIONS,
    ),
    Regla(
        "AT-004",
        E,
        "Attestation does not verify",
        f"{PEP740_VERIFY}; pypi-attestations `Attestation.verify`",
        URL_PYPI_ATTESTATIONS,
    ),
    Regla(
        "AT-005",
        A,
        "Attested release, but the locked files carry no attestation",
        f"{PEP740_SIMPLE}; {ATTESTATIONS}",
        URL_PEP740,
    ),
    # --- Lectura del lockfile y del índice ----------------------------------------------
    Regla("LOCK-001", INC, "The lockfile cannot be read", LOCKFILES, URL_PEP751),
    Regla("LOCK-002", INF, "Not pinned to an exact version: not checked", LOCKFILES, URL_PEP751),
    Regla("SRC-001", INF, "Not installed from PyPI: not checked", LOCKFILES, URL_PEP751),
    Regla(
        "SRC-002",
        A,
        "The pinned release or locked files do not match PyPI",
        f"{PEP691_FILES}; {PEP751}",
        URL_PEP691,
    ),
    Regla(
        "SRC-003",
        INF,
        "Custom package index: results describe PyPI",
        "pip requirements file format (--index-url, --extra-index-url, --find-links)",
        "https://pip.pypa.io/en/stable/reference/requirements-file-format/",
    ),
    Regla(
        "NET-001",
        INC,
        "PyPI data could not be retrieved",
        f"{PEP691_FILES}; {INTEGRITY}",
        URL_INTEGRITY,
    ),
)

REGLAS: dict[str, Regla] = {r.id: r for r in _REGLAS}

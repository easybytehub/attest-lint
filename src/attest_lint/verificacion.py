"""AT-004: verificación criptográfica con la librería oficial `pypi-attestations`.

Es opcional (`pip install 'attest-lint[verify]'`): trae Sigstore y su cadena de
dependencias, y el aviso de regresión no la necesita.

**Contra qué digest se verifica importa.** Si el lockfile fija el sha256 del fichero,
se verifica contra ese: la atestación tiene que cubrir exactamente lo que vas a
instalar. Si no lo fija, se usa el sha256 que publica PyPI, y el informe lo dice,
porque entonces la comprobación es «PyPI es coherente consigo mismo», que es menos.
"""

from __future__ import annotations

import logging
from typing import Any

VERIFICADA, FALLIDA, INDETERMINADA = "verified", "failed", "undetermined"


def disponible() -> bool:
    try:
        import pypi_attestations  # noqa: F401
    except ImportError:
        return False
    return True


def _tipos_soportados() -> set[str]:
    import pypi_attestations

    tipos = set()
    for nombre in dir(pypi_attestations):
        clase = getattr(pypi_attestations, nombre)
        campos = getattr(clase, "model_fields", {})
        if nombre.endswith("Publisher") and "kind" in campos:
            tipos.add(str(campos["kind"].default))
    return tipos


def verifica(
    procedencia: dict[str, Any], fichero: str, digest: str, offline: bool
) -> tuple[str, str]:
    """(resultado, explicación). `offline` no refresca la raíz de confianza de Sigstore."""
    from pydantic import ValidationError
    from pypi_attestations import AttestationError, Distribution, Provenance

    # sigstore avisa por logging de cosas normales ("TUF repository is loaded in offline
    # mode"); sin handler, Python las imprimiría en stderr en mitad del informe.
    logging.getLogger("sigstore").setLevel(logging.ERROR)
    try:
        distribucion = Distribution(name=fichero, digest=digest)
    except ValidationError:
        return INDETERMINADA, f"`{fichero}` is not a valid wheel or sdist filename."
    try:
        modelo = Provenance.model_validate(procedencia)
    except ValidationError as exc:
        tipos = {
            str((b.get("publisher") or {}).get("kind"))
            for b in procedencia.get("attestation_bundles", [])
            if isinstance(b, dict)
        }
        desconocidos = tipos - _tipos_soportados()
        if desconocidos:
            return INDETERMINADA, (
                f"publisher kind {', '.join(sorted(desconocidos))} is not supported by the "
                "installed pypi-attestations."
            )
        primero = exc.errors()[0]["msg"] if exc.errors() else str(exc)
        return FALLIDA, f"malformed provenance object: {primero}."
    total = 0
    for paquete in modelo.attestation_bundles:
        for atestacion in paquete.attestations:
            total += 1
            try:
                atestacion.verify(paquete.publisher, distribucion, offline=offline)
            except AttestationError as exc:
                return FALLIDA, str(exc).splitlines()[0]
            except Exception as exc:  # TUF sin red, raíz de confianza caducada…
                return INDETERMINADA, f"{type(exc).__name__}: {exc}".splitlines()[0]
    if not total:
        return FALLIDA, "the provenance object contains no attestation."
    return VERIFICADA, f"{total} attestation(s) verified."

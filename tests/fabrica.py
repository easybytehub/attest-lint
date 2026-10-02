"""Índices y procedencias sintéticos para los casos que PyPI no ofrece a demanda."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from tests.conftest import Grabado


def sha(texto: str) -> str:
    return hashlib.sha256(texto.encode()).hexdigest()


def rueda(nombre: str, version: str) -> str:
    return f"{nombre.replace('-', '_')}-{version}-py3-none-any.whl"


def url_procedencia(nombre: str, version: str) -> str:
    return f"https://pypi.org/integrity/{nombre}/{version}/{rueda(nombre, version)}/provenance"


def procedencia(
    repo: str = "org/demo",
    workflow: str = "release.yml",
    environment: str | None = None,
    kind: str = "GitHub",
) -> dict[str, Any]:
    editor = {"kind": kind, "repository": repo, "workflow": workflow, "environment": environment}
    return {"version": 1, "attestation_bundles": [{"publisher": editor, "attestations": []}]}


def pypi(nombre: str, versiones: Sequence[tuple[str, str, dict[str, Any] | None]]) -> Grabado:
    """versiones: (versión, upload-time, procedencia o None). Devuelve el transporte."""
    ficheros, extra = [], {}
    for version, cuando, prov in versiones:
        url = url_procedencia(nombre, version) if prov else None
        ficheros.append(
            {
                "filename": rueda(nombre, version),
                "hashes": {"sha256": sha(rueda(nombre, version))},
                "provenance": url,
                "upload-time": cuando,
                "yanked": False,
            }
        )
        if url:
            extra[url] = prov
    extra[f"https://pypi.org/simple/{nombre}/"] = {
        "meta": {"api-version": "1.4"},
        "name": nombre,
        "versions": [v for v, _, _ in versiones],
        "files": ficheros,
    }
    return Grabado(extra)

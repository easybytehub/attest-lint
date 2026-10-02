"""Cómo se presenta el informe: texto, JSON y SARIF (todo en inglés).

SARIF no está por completismo: es lo que GitHub ingiere en la pestaña Security, y cada
hallazgo apunta a la línea del lockfile donde se fija el paquete.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attest_lint.catalogo import REGLAS
from attest_lint.hallazgos import Informe, Severidad

_NIVEL_SARIF = {
    Severidad.ERROR: "error",
    Severidad.AVISO: "warning",
    Severidad.INFO: "note",
    Severidad.INCOMPLETO: "note",
}
AVISO = (
    "A regression or a publisher change is a signal to review, not proof of compromise; "
    "zero findings does not mean your dependencies are safe."
)


def texto(informe: Informe, color: bool = True) -> str:
    rojo, amarillo, azul, gris, fin = (
        ("\033[31m", "\033[33m", "\033[34m", "\033[90m", "\033[0m") if color else ("",) * 5
    )
    tinte = {
        Severidad.ERROR: rojo,
        Severidad.AVISO: amarillo,
        Severidad.INFO: "",
        Severidad.INCOMPLETO: azul,
    }
    sangria = " " * 13
    comprobados = sum(1 for p in informe.paquetes if p.get("checked"))
    lineas = [
        f"attest-lint · {len(informe.lockfiles)} lockfile(s) · {comprobados} package(s) "
        f"checked against PyPI · window: {informe.ventana or 'all releases'}",
        "",
    ]
    if not informe.hallazgos:
        lineas += ["No findings.", ""]
    for h in informe.hallazgos:
        lineas.append(f"{tinte[h.severidad]}{h.cabecera()}{fin}")
        lineas += [f"{sangria}{d}" for d in h.detalle.splitlines()]
        lineas.append(f"{gris}{sangria}citation: {h.norma}{fin}")
        lineas.append("")

    def cuenta(n: int, s: str, p: str) -> str:
        return f"{n} {s if n == 1 else p}"

    resumen = [
        cuenta(len(informe.errores), "error", "errors"),
        cuenta(len(informe.avisos), "warning", "warnings"),
        f"{len(informe.de(Severidad.INFO))} info",
        f"{len(informe.de(Severidad.INCOMPLETO))} undetermined",
    ]
    if informe.permitidos:
        resumen.append(f"{informe.permitidos} allowlisted")
    lineas.append(" · ".join(resumen))
    lineas.append(f"{gris}{AVISO}{fin}")
    return "\n".join(lineas)


def como_json(informe: Informe) -> str:
    datos: dict[str, Any] = {
        "lockfiles": informe.lockfiles,
        "window": informe.ventana,
        "summary": {
            "errors": len(informe.errores),
            "warnings": len(informe.avisos),
            "info": len(informe.de(Severidad.INFO)),
            "undetermined": len(informe.de(Severidad.INCOMPLETO)),
            "allowlisted": informe.permitidos,
            "packages_checked": sum(1 for p in informe.paquetes if p.get("checked")),
        },
        "findings": [
            {
                "rule": h.regla,
                "severity": h.severidad.value,
                "package": h.paquete,
                "title": h.titulo,
                "detail": h.detalle,
                "citation": h.norma,
                "url": h.url,
                "file": h.fichero,
                "line": h.linea or None,
            }
            for h in informe.hallazgos
        ],
        "packages": informe.paquetes,
        "notice": AVISO,
    }
    return json.dumps(datos, ensure_ascii=False, indent=2)


def _uri(fichero: str) -> str:
    """Relativa al directorio de trabajo (la raíz del checkout en CI, que es lo que GitHub
    sabe anclar); `file://` absoluta si el fichero está fuera de él."""
    ruta = Path(fichero)
    if not ruta.is_absolute():
        return ruta.as_posix()
    absoluta = ruta.resolve()  # /var y /private/var son el mismo sitio en macOS
    try:
        return absoluta.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return absoluta.as_uri()


def como_sarif(informe: Informe, version: str) -> str:
    reglas_vistas: dict[str, dict[str, Any]] = {}
    resultados: list[dict[str, Any]] = []
    for h in informe.hallazgos:
        regla = REGLAS[h.regla]
        descriptor: dict[str, Any] = {
            "id": h.regla,
            "shortDescription": {"text": regla.titulo},
            "fullDescription": {"text": regla.norma},
            "defaultConfiguration": {"level": _NIVEL_SARIF[regla.severidad]},
        }
        if regla.url:
            descriptor["helpUri"] = regla.url
        reglas_vistas.setdefault(h.regla, descriptor)
        sujeto = f"{h.paquete}: " if h.paquete else ""
        resultados.append(
            {
                "ruleId": h.regla,
                "level": _NIVEL_SARIF[h.severidad],
                "message": {"text": f"{sujeto}{h.titulo}. {h.detalle}\nCitation: {h.norma}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _uri(h.fichero)},
                            "region": {"startLine": max(h.linea, 1)},
                        }
                    }
                ],
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "attest-lint",
                        "version": version,
                        "informationUri": "https://github.com/easybytehub/attest-lint",
                        "rules": list(reglas_vistas.values()),
                    }
                },
                "results": resultados,
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)

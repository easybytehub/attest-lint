"""Graba las respuestas de PyPI que necesitan los tests (es lo único que toca la red).

Ejecuta attest-lint de verdad sobre los lockfiles de `tests/fixtures/lockfiles/` con un
transporte que, además de pedir, guarda cada respuesta en `tests/fixtures/pypi/`. Así
las fixtures son exactamente las peticiones que hace la herramienta, ni una más.

Del índice simple se guardan sólo las claves que la herramienta lee (`filename`,
`hashes`, `provenance`, `upload-time`, `yanked`) para que el repositorio no cargue
megas de `core-metadata`; los valores no se tocan. Las procedencias se guardan enteras.

    python scripts/grabar-fixtures.py
"""

from __future__ import annotations

import datetime
import gzip
import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from attest_lint import cli, verificacion  # noqa: E402
from attest_lint.pypi import Respuesta, transporte_http  # noqa: E402

DESTINO = RAIZ / "tests" / "fixtures" / "pypi"
LOCKS = RAIZ / "tests" / "fixtures" / "lockfiles"
CLAVES = ("filename", "hashes", "provenance", "upload-time", "yanked")


def relativa(url: str) -> str:
    resto = url.removeprefix("https://pypi.org/").rstrip("/")
    return resto.removesuffix("/provenance") + ".json.gz"


def main() -> int:
    manifiesto: dict[str, dict[str, object]] = {}
    hoy = datetime.date.today().isoformat()

    def graba(url: str, acepta: str) -> Respuesta:
        r = transporte_http(url, acepta)
        entrada: dict[str, object] = {"status": r.estado, "recorded": hoy}
        if r.estado == 200:
            datos = json.loads(r.cuerpo)
            if "files" in datos:
                datos["files"] = [{k: f[k] for k in CLAVES if k in f} for f in datos["files"]]
            cuerpo = json.dumps(datos, sort_keys=True).encode()
            ruta = DESTINO / relativa(url)
            ruta.parent.mkdir(parents=True, exist_ok=True)
            ruta.write_bytes(gzip.compress(cuerpo, mtime=0))
            entrada["file"] = relativa(url)
            r = Respuesta(200, cuerpo)
        manifiesto[url] = entrada
        return r

    casos = [
        ["requirements.txt", "--verify"],
        ["uv.lock"],
        ["pylock.toml"],
        ["poetry.lock"],
        ["requirements-hashes.txt"],
    ]
    for caso in casos:
        argv = [str(LOCKS / caso[0]), *caso[1:], "--no-cache", "--format", "json"]
        codigo = cli.main(argv, transporte=graba, verificador=verificacion.verifica)
        print(f"{caso}: exit {codigo}", file=sys.stderr)
    (DESTINO / "MANIFEST.json").write_text(
        json.dumps(dict(sorted(manifiesto.items())), indent=1) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

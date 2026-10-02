"""Los tests no tocan la red: responden las grabaciones de tests/fixtures/pypi/."""

from __future__ import annotations

import gzip
import json
import socket
from pathlib import Path
from typing import Any

import pytest

from attest_lint import cli, pypi
from attest_lint.pypi import Respuesta
from attest_lint.reglas import Verificador

FIX = Path(__file__).parent / "fixtures"
LOCKS = FIX / "lockfiles"
PYPI = FIX / "pypi"
MANIFIESTO: dict[str, dict[str, Any]] = json.loads(
    (PYPI / "MANIFEST.json").read_text(encoding="utf-8")
)


class Grabado:
    """Transporte que responde con lo grabado y falla ante cualquier URL no grabada."""

    def __init__(self, extra: dict[str, Any] | None = None) -> None:
        self.extra = extra or {}
        self.pedidas: list[str] = []

    def __call__(self, url: str, acepta: str) -> Respuesta:
        self.pedidas.append(url)
        if url in self.extra:
            valor = self.extra[url]
            if isinstance(valor, Respuesta):
                return valor
            if isinstance(valor, Exception):
                raise valor
            return Respuesta(200, json.dumps(valor).encode())
        entrada = MANIFIESTO.get(url)
        if entrada is None:
            raise AssertionError(f"unrecorded URL: {url}")
        if entrada["status"] != 200:
            return Respuesta(int(entrada["status"]))
        return Respuesta(200, gzip.decompress((PYPI / entrada["file"]).read_bytes()))


def grabado(url: str) -> dict[str, Any]:
    datos: dict[str, Any] = json.loads(
        gzip.decompress((PYPI / MANIFIESTO[url]["file"]).read_bytes())
    )
    return datos


@pytest.fixture(autouse=True)
def sin_red(monkeypatch: pytest.MonkeyPatch) -> None:
    def prohibido(*_: object, **__: object) -> None:
        raise AssertionError("tests must not touch the network")

    monkeypatch.setattr(socket.socket, "connect", prohibido)
    monkeypatch.setattr(socket, "create_connection", prohibido)
    monkeypatch.setattr(socket, "getaddrinfo", prohibido)
    # Las respuestas grabadas no necesitan el límite de 10 peticiones/s (test_pypi lo prueba).
    monkeypatch.setattr(pypi, "INTERVALO", 0.0)


def ejecuta(
    capsys: pytest.CaptureFixture[str],
    *argv: str,
    transporte: Any = None,
    verificador: Verificador | None = None,
) -> tuple[int, str, str]:
    args = list(argv)
    if "--offline" not in args and "--cache-dir" not in args:
        args.append("--no-cache")
    codigo = cli.main(args, transporte=transporte or Grabado(), verificador=verificador)
    out, err = capsys.readouterr()
    return codigo, out, err

"""El cliente de PyPI: ritmo, reintentos, caché, --offline y cabeceras."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from attest_lint import pypi
from attest_lint.pypi import (
    ACEPTA_INDICE,
    INTERVALO,
    USER_AGENT,
    Cache,
    Cliente,
    ErrorDeRed,
    Respuesta,
    cache_por_defecto,
    transporte_http,
)

URL = "https://pypi.org/simple/demo/"
INDICE = {"name": "demo", "files": []}


class Reloj:
    def __init__(self) -> None:
        self.t = 1000.0
        self.esperas: list[float] = []

    def __call__(self) -> float:
        return self.t

    def duerme(self, s: float) -> None:
        self.esperas.append(s)
        self.t += s


class Contador:
    def __init__(self, *respuestas: Respuesta) -> None:
        self.respuestas = list(respuestas)
        self.urls: list[str] = []

    def __call__(self, url: str, acepta: str) -> Respuesta:
        self.urls.append(url)
        if len(self.respuestas) > 1:
            return self.respuestas.pop(0)
        return self.respuestas[0]


def _ok(datos: dict[str, Any] = INDICE) -> Respuesta:
    return Respuesta(200, json.dumps(datos).encode())


def test_at_most_ten_requests_per_second() -> None:
    assert INTERVALO == 0.1  # el valor publicado (conftest lo anula sólo para las grabaciones)
    reloj = Reloj()
    cliente = Cliente(Contador(_ok()), reloj=reloj, dormir=reloj.duerme, intervalo=INTERVALO)
    for n in ("a", "b", "c"):
        cliente.indice(n)
    assert cliente.peticiones == 3
    assert reloj.esperas == [pytest.approx(0.1), pytest.approx(0.1)]


def test_retries_honour_retry_after_then_give_up() -> None:
    reloj = Reloj()
    transporte = Contador(Respuesta(429, reintentar_en=3), Respuesta(503), _ok())
    cliente = Cliente(transporte, reloj=reloj, dormir=reloj.duerme, intervalo=0)
    assert cliente.indice("demo") == INDICE
    assert reloj.esperas == [3, 2.0] and len(transporte.urls) == 3
    siempre_mal = Cliente(Contador(Respuesta(500)), reloj=reloj, dormir=reloj.duerme)
    with pytest.raises(ErrorDeRed, match="HTTP 500"):
        siempre_mal.indice("demo")


def test_404_is_none_and_memoised() -> None:
    transporte = Contador(Respuesta(404))
    cliente = Cliente(transporte, intervalo=0)
    assert cliente.indice("demo") is None and cliente.indice("demo") is None
    assert len(transporte.urls) == 1


@pytest.mark.parametrize(
    "respuesta",
    [Respuesta(200, b"not json"), Respuesta(200, b"[]"), Respuesta(200, b'{"name": "x"}')],
)
def test_bad_index_bodies_are_network_errors(respuesta: Respuesta) -> None:
    with pytest.raises(ErrorDeRed):
        Cliente(Contador(respuesta), intervalo=0).indice("demo")


def test_provenance_url_must_be_pypi_https() -> None:
    cliente = Cliente(Contador(_ok()), intervalo=0)
    for url in ("http://pypi.org/integrity/x", "https://evil.example/integrity/x"):
        with pytest.raises(ErrorDeRed, match="unexpected provenance URL"):
            cliente.procedencia(url)


def test_cache_ttl_and_offline(tmp_path: Path) -> None:
    ahora = [5000.0]
    cache = Cache(tmp_path / "c", ahora=lambda: ahora[0])
    transporte = Contador(_ok())
    Cliente(transporte, cache, intervalo=0, ttl_indice=60).indice("demo")
    Cliente(transporte, cache, intervalo=0, ttl_indice=60).indice("demo")
    assert len(transporte.urls) == 1  # la segunda salió de la caché
    ahora[0] += 61
    Cliente(transporte, cache, intervalo=0, ttl_indice=60).indice("demo")
    assert len(transporte.urls) == 2  # caducada: se vuelve a pedir
    ahora[0] += 10**6
    offline = Cliente(Contador(Respuesta(500)), cache, offline=True)
    assert offline.indice("demo") == INDICE  # --offline ignora la caducidad
    with pytest.raises(ErrorDeRed, match="not in the cache"):
        offline.indice("other")


def test_fresh_bypasses_the_cache(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    transporte = Contador(_ok())
    cliente = Cliente(transporte, cache, intervalo=0)
    cliente.indice("demo")
    cliente.indice("demo", fresco=True)
    assert len(transporte.urls) == 2


def test_broken_cache_is_ignored(tmp_path: Path) -> None:
    cache = Cache(tmp_path)
    cache.escribe(URL, _ok())
    next(tmp_path.glob("*.json")).write_text("{broken", encoding="utf-8")
    assert cache.lee(URL, None) is None
    bloqueado = tmp_path / "file"
    bloqueado.write_text("x", encoding="utf-8")
    Cache(bloqueado / "sub").escribe(URL, _ok())  # no puede crear el directorio: no pasa nada


def test_default_cache_dir_respects_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATTEST_LINT_CACHE_DIR", "somewhere")
    assert cache_por_defecto() == Path("somewhere")
    monkeypatch.delenv("ATTEST_LINT_CACHE_DIR")
    assert "attest-lint" in str(cache_por_defecto())


def test_http_transport_identifies_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    vistas: list[urllib.request.Request] = []

    class Falsa:
        status = 200

        def __enter__(self) -> Falsa:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self, _n: int) -> bytes:
            return b"{}"

    def abre(peticion: urllib.request.Request) -> Falsa:
        vistas.append(peticion)
        return Falsa()

    monkeypatch.setattr(pypi, "_abre", abre)
    assert transporte_http(URL, ACEPTA_INDICE).estado == 200
    assert vistas[0].get_header("User-agent") == USER_AGENT
    assert vistas[0].get_header("Accept") == ACEPTA_INDICE
    assert USER_AGENT.startswith("attest-lint/")


def test_http_transport_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def abre(*_: object, **__: object) -> None:
        raise urllib.error.URLError("no route")

    monkeypatch.setattr(pypi, "_abre", abre)
    with pytest.raises(ErrorDeRed, match="no route"):
        transporte_http(URL, ACEPTA_INDICE)

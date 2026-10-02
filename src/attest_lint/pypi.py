"""El acceso a PyPI: dos rutas, un límite de ritmo y una caché en disco.

- Índice simple en JSON (PEP 691, con los campos de PEP 700 y la clave `provenance` de
  PEP 740): `GET https://pypi.org/simple/<proyecto>/` con
  `Accept: application/vnd.pypi.simple.v1+json`. Una petición por paquete trae todo el
  historial y dice, fichero a fichero, si hay atestación.
- Integrity API: `GET https://pypi.org/integrity/<proyecto>/<versión>/<fichero>/provenance`.
  Sólo hace falta para saber *quién* publicó (AT-002) y para verificar (AT-004).

**Buen ciudadano**: User-Agent que dice quién somos, como mucho ~10 peticiones por
segundo, reintentos sólo ante 429/5xx y respetando `Retry-After`, y caché en disco para
no repetir lo que ya se preguntó. `--offline` sólo lee la caché: un dato que falta es
`NET-001`, nunca un «no hay atestación».
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from attest_lint import __version__

URL_INDICE = "https://pypi.org/simple/{}/"
ACEPTA_INDICE = "application/vnd.pypi.simple.v1+json"
ACEPTA_INTEGRIDAD = "application/vnd.pypi.integrity.v1+json"
USER_AGENT = f"attest-lint/{__version__} (+https://github.com/easybytehub/attest-lint)"
INTERVALO = 0.1
"""Segundos mínimos entre dos peticiones: ≤ 10 por segundo."""
TTL_INDICE = 3600
"""El índice cambia con cada publicación: una hora."""
TTL_PROCEDENCIA = 7 * 86400
"""La procedencia de un fichero ya publicado casi nunca cambia (PEP 740 permite añadir
atestaciones *a posteriori*, no quitar las que había): una semana."""
LIMITE = 128 * 1024 * 1024
_REINTENTABLES = {429, 500, 502, 503, 504}


class ErrorDeRed(Exception):
    """No se ha podido obtener un dato de PyPI (red, HTTP, caché vacía en --offline)."""


class SinConexion(ErrorDeRed):
    """No se llega a PyPI (DNS, conexión, tiempo de espera). Tras la primera, el cliente no
    vuelve a intentarlo en esta ejecución: esperar 30 s por paquete no aporta nada."""


class _SoloPyPI(urllib.request.HTTPRedirectHandler):
    """Sólo sigue redirecciones a https://pypi.org: lo que no venga de ahí no es PyPI."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        destino = urlsplit(newurl)
        if destino.scheme != "https" or destino.hostname != "pypi.org":
            raise ErrorDeRed(f"{req.full_url}: redirect to {newurl} refused (not https://pypi.org)")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_ABRIDOR = urllib.request.build_opener(_SoloPyPI)


def _abre(peticion: urllib.request.Request) -> Any:
    return _ABRIDOR.open(peticion, timeout=30)


@dataclass(frozen=True)
class Respuesta:
    estado: int
    cuerpo: bytes = b""
    reintentar_en: float | None = None


class Transporte(Protocol):
    def __call__(self, url: str, acepta: str) -> Respuesta: ...


def transporte_http(url: str, acepta: str) -> Respuesta:
    peticion = urllib.request.Request(  # noqa: S310 - sólo https://pypi.org (ver Cliente)
        url, headers={"User-Agent": USER_AGENT, "Accept": acepta}
    )
    try:
        with _abre(peticion) as r:
            cuerpo = r.read(LIMITE + 1)
            if len(cuerpo) > LIMITE:
                raise ErrorDeRed(f"{url}: response larger than {LIMITE} bytes")
            return Respuesta(r.status, cuerpo)
    except urllib.error.HTTPError as exc:
        espera = exc.headers.get("Retry-After") if exc.headers else None
        try:
            segundos = float(espera) if espera else None
        except ValueError:
            segundos = None
        return Respuesta(exc.code, b"", segundos)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        motivo = getattr(exc, "reason", None) or exc
        raise SinConexion(f"{url}: {motivo}") from exc


def cache_por_defecto() -> Path:
    if propio := os.environ.get("ATTEST_LINT_CACHE_DIR"):
        return Path(propio)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "attest-lint" / "Cache"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "attest-lint"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "attest-lint"


class Cache:
    """Un fichero JSON por URL. Es una ayuda, no una fuente: si falla, se ignora."""

    def __init__(self, directorio: Path, ahora: Callable[[], float] = time.time) -> None:
        self.directorio = directorio
        self._ahora = ahora

    def _ruta(self, url: str) -> Path:
        return self.directorio / f"{hashlib.sha256(url.encode()).hexdigest()}.json"

    def lee(self, url: str, ttl: float | None) -> Respuesta | None:
        """La respuesta guardada; None si no hay o si caducó (ttl None = no caduca)."""
        try:
            datos = json.loads(self._ruta(url).read_text(encoding="utf-8"))
            if datos["url"] != url:
                return None
            if ttl is not None and self._ahora() - float(datos["fetched"]) > ttl:
                return None
            return Respuesta(int(datos["status"]), str(datos["body"]).encode("utf-8"))
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def escribe(self, url: str, respuesta: Respuesta) -> None:
        ruta = self._ruta(url)
        temporal = ruta.with_suffix(f".{os.getpid()}.tmp")
        datos = {
            "url": url,
            "fetched": self._ahora(),
            "status": respuesta.estado,
            "body": respuesta.cuerpo.decode("utf-8", "replace"),
        }
        try:
            self.directorio.mkdir(parents=True, exist_ok=True)
            temporal.write_text(json.dumps(datos), encoding="utf-8")
            os.replace(temporal, ruta)
        except OSError:
            pass


class Cliente:
    def __init__(
        self,
        transporte: Transporte = transporte_http,
        cache: Cache | None = None,
        *,
        offline: bool = False,
        ttl_indice: float = TTL_INDICE,
        intervalo: float | None = None,
        reloj: Callable[[], float] = time.monotonic,
        dormir: Callable[[float], None] = time.sleep,
    ) -> None:
        self._transporte = transporte
        self.cache = cache
        self.offline = offline
        self.ttl_indice = ttl_indice
        self.intervalo = INTERVALO if intervalo is None else intervalo
        self._reloj = reloj
        self._dormir = dormir
        self._ultima: float | None = None
        self._memoria: dict[str, Any] = {}
        self._sin_conexion = ""
        self.peticiones = 0

    def indice(self, nombre: str, *, fresco: bool = False) -> dict[str, Any] | None:
        """El índice simple del proyecto (PEP 691); None si PyPI no lo tiene (404)."""
        url = URL_INDICE.format(nombre)
        datos: dict[str, Any] | None = self._obtiene(
            url, ACEPTA_INDICE, self.ttl_indice, fresco, _es_indice
        )
        return datos

    def procedencia(self, url: str) -> dict[str, Any]:
        """El objeto de procedencia (PEP 740) de un fichero que el índice dice que lo tiene."""
        partes = urlsplit(url)
        if partes.scheme != "https" or partes.hostname != "pypi.org":
            raise ErrorDeRed(f"unexpected provenance URL (not https://pypi.org): {url}")
        datos: dict[str, Any] | None = self._obtiene(
            url, ACEPTA_INTEGRIDAD, TTL_PROCEDENCIA, False, _es_procedencia
        )
        if datos is None:
            raise ErrorDeRed(f"{url}: the index announces a provenance but it returns 404")
        return datos

    def _obtiene(self, url: str, acepta: str, ttl: float, fresco: bool, valida: _Validador) -> Any:
        if not fresco and url in self._memoria:
            return self._memoria[url]
        respuesta = None
        if self.cache is not None and (self.offline or not fresco):
            respuesta = self.cache.lee(url, None if self.offline else ttl)
        if respuesta is not None:
            try:
                datos = _interpreta(url, respuesta, valida)
            except ErrorDeRed:
                if self.offline:
                    raise
                # Envoltorio válido y cuerpo corrupto: no se arrastra durante todo el TTL.
                datos = _interpreta(url, self._pide_y_guarda(url, acepta), valida)
        else:
            if self.offline:
                raise ErrorDeRed(f"{url}: not in the cache (--offline)")
            datos = _interpreta(url, self._pide_y_guarda(url, acepta), valida)
        self._memoria[url] = datos
        return datos

    def _pide_y_guarda(self, url: str, acepta: str) -> Respuesta:
        respuesta = self._pide(url, acepta)
        if respuesta.estado in (200, 404) and self.cache is not None:
            self.cache.escribe(url, respuesta)  # se valida al leer; si no vale, se repide
        return respuesta

    def _pide(self, url: str, acepta: str) -> Respuesta:
        respuesta = Respuesta(0)
        for intento in range(3):
            if self._ultima is not None:
                espera = self._ultima + self.intervalo - self._reloj()
                if espera > 0:
                    self._dormir(espera)
            self._ultima = self._reloj()
            if self._sin_conexion:
                raise SinConexion(
                    f"{url}: not tried, PyPI was unreachable earlier in this run "
                    f"({self._sin_conexion})"
                )
            self.peticiones += 1
            try:
                respuesta = self._transporte(url, acepta)
            except SinConexion as exc:
                self._sin_conexion = str(exc).split(": ", 1)[-1]
                raise
            if respuesta.estado not in _REINTENTABLES or intento == 2:
                return respuesta
            self._dormir(min(respuesta.reintentar_en or 2.0**intento, 30.0))
        return respuesta


_Validador = Callable[[dict[str, Any]], str | None]


def _es_indice(datos: dict[str, Any]) -> str | None:
    if isinstance(datos.get("files"), list):
        return None
    return "not a PEP 691 JSON response (no `files` list)"


def _es_procedencia(datos: dict[str, Any]) -> str | None:
    if isinstance(datos.get("attestation_bundles"), list):
        return None
    return "not a PEP 740 provenance object"


def _interpreta(url: str, respuesta: Respuesta, valida: _Validador) -> Any:
    if respuesta.estado == 404:
        return None
    if respuesta.estado != 200:
        raise ErrorDeRed(f"{url}: HTTP {respuesta.estado}")
    try:
        datos = json.loads(respuesta.cuerpo)
    except ValueError as exc:
        raise ErrorDeRed(f"{url}: invalid JSON") from exc
    if not isinstance(datos, dict):
        raise ErrorDeRed(f"{url}: unexpected JSON")
    problema = valida(datos)
    if problema:
        raise ErrorDeRed(f"{url}: {problema}")
    return datos

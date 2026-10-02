"""Lectura de lockfiles: pylock.toml (PEP 751), uv.lock, poetry.lock y requirements.txt.

**La regla es no adivinar.** Un lockfile que no se entiende entero da `LOCK-001` y la
salida 2: un informe limpio sobre la mitad de las dependencias es peor que ninguno,
porque quien lo lee cree que se miró todo. Una entrada que sí se entiende pero no se
puede comprobar (sin versión exacta, instalada desde git o desde una ruta) se informa y
se salta, sin parar el resto.

**Espejos e índices propios.** Un Artifactory o un devpi que replica PyPI sirve los
mismos ficheros con los mismos sha256. Si el lockfile fija el sha256, la entrada se
comprueba contra PyPI igual que cualquier otra y, si el fichero no es el de PyPI, lo
dice SRC-002. Si no fija ningún sha256 no hay forma de saber que es el mismo fichero, y
la entrada se salta (SRC-001). La regla es la misma en los cuatro formatos.

Sólo `pylock.toml` es un estándar. `uv.lock` y `poetry.lock` son formatos propios de
cada herramienta: se leen las versiones que existen hoy (`version = 1` de uv;
`lock-version` 1.x y 2.x de Poetry) y cualquier otra se rechaza en vez de leerse a
medias.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import InvalidName, canonicalize_name

from attest_lint.catalogo import REGLAS
from attest_lint.hallazgos import Hallazgo

TIPOS = ("pylock", "uv", "poetry", "requirements")
_INDICES_PYPI = {"https://pypi.org/simple", "https://pypi.python.org/simple"}
_HOSTS_PYPI = {"files.pythonhosted.org", "pypi.org"}


class Ilegible(Exception):
    """El lockfile no se puede leer con fiabilidad."""


@dataclass(frozen=True)
class Fijado:
    """Una entrada del lockfile."""

    nombre: str
    """Nombre normalizado (PEP 503), o el texto de la línea si no es un paquete de índice."""
    version: str | None
    lockfile: str
    linea: int = 0
    ficheros: tuple[tuple[str, str], ...] = ()
    """(nombre de fichero, sha256) que el lockfile fija para esta versión."""
    hashes: frozenset[str] = frozenset()
    """sha256 sin nombre de fichero (requirements.txt con --hash)."""
    fuera_de_pypi: str = ""
    """Si no se puede comprobar contra PyPI, de dónde se instala."""
    via: str = ""
    """Índice propio o espejo del que se resolvió; se comprueba contra PyPI por sha256."""
    sin_fijar: str = ""
    """Si no hay versión exacta, el especificador que hay en su lugar."""

    @property
    def tiene_sha256(self) -> bool:
        return bool(self.ficheros or self.hashes)


@dataclass
class Lectura:
    fijados: list[Fijado] = field(default_factory=list)
    hallazgos: list[Hallazgo] = field(default_factory=list)
    ilegible: bool = False


def tipo_de(ruta: Path) -> str | None:
    """El formato por el nombre del fichero (PEP 751 fija el de pylock)."""
    nombre = ruta.name
    if nombre == "uv.lock":
        return "uv"
    if nombre == "poetry.lock":
        return "poetry"
    if re.fullmatch(r"pylock(\.[^.]+)?\.toml", nombre):
        return "pylock"
    if nombre.endswith((".txt", ".in")) or nombre.startswith("requirements"):
        return "requirements"
    return None


def lee(ruta: Path, tipo: str | None = None) -> Lectura:
    tipo = tipo or tipo_de(ruta)
    fichero = str(ruta)
    if tipo is None:
        return _ilegible(
            fichero,
            "Unrecognised lockfile name. Expected pylock.toml, pylock.<name>.toml, uv.lock, "
            "poetry.lock or a requirements file (*.txt); use --type to force a format.",
        )
    try:
        if tipo == "requirements":
            return _requirements(ruta)
        texto = ruta.read_text(encoding="utf-8")
        datos = tomllib.loads(texto)
        lector = {"pylock": _pylock, "uv": _uv, "poetry": _poetry}[tipo]
        return Lectura(fijados=lector(datos, texto, fichero))
    except OSError as exc:
        return _ilegible(fichero, f"{exc.strerror or exc}.")
    except UnicodeDecodeError:
        return _ilegible(fichero, "Not valid UTF-8.")
    except tomllib.TOMLDecodeError as exc:
        return _ilegible(fichero, f"Invalid TOML: {exc}.")
    except Ilegible as exc:
        return _ilegible(fichero, f"{exc}.")


def _ilegible(fichero: str, detalle: str, linea: int = 0) -> Lectura:
    h = REGLAS["LOCK-001"].hallazgo(detalle, fichero=fichero, linea=linea)
    return Lectura(hallazgos=[h], ilegible=True)


# --- Utilidades ---------------------------------------------------------------------------


def _es_pypi(indice: str) -> bool:
    return indice.strip().rstrip("/").lower() in _INDICES_PYPI


def _nombre_de_url(url: str) -> str:
    return unquote(urlsplit(url).path.rsplit("/", 1)[-1])


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _sha256(valor: object) -> str | None:
    """`sha256:<hex>` (uv, Poetry) → `<hex>`; cualquier otro algoritmo → None."""
    if isinstance(valor, str):
        algoritmo, _, digest = valor.partition(":")
        if algoritmo.lower() == "sha256" and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            return digest.lower()
    return None


def _lineas(texto: str, tabla: str) -> list[int]:
    """Línea del `name = ...` de cada `[[tabla]]`, en orden (tomllib no da posiciones)."""
    cabecera = re.compile(r"^\s*\[\[\s*" + re.escape(tabla) + r"\s*\]\]\s*(#.*)?$")
    lineas: list[int] = []
    dentro = False
    for n, linea in enumerate(texto.splitlines(), 1):
        if cabecera.match(linea):
            lineas.append(n)
            dentro = True
        elif dentro and re.match(r"^\s*name\s*=", linea):
            lineas[-1] = n
            dentro = False
        elif dentro and re.match(r"^\s*\[", linea):
            dentro = False
    return lineas


def _lista(datos: dict[str, Any], clave: str, que: str) -> list[dict[str, Any]]:
    valor = datos.get(clave, [])
    if not isinstance(valor, list) or not all(isinstance(p, dict) for p in valor):
        raise Ilegible(f"`{clave}` is not an array of {que} tables")
    return valor


def _nombre(p: dict[str, Any], i: int) -> str:
    nombre = p.get("name")
    if not isinstance(nombre, str) or not nombre:
        raise Ilegible(f"entry #{i + 1} has no name")
    try:
        return canonicalize_name(nombre, validate=True)
    except InvalidName as exc:
        raise Ilegible(f"entry #{i + 1}: invalid package name {nombre!r}") from exc


def _version(p: dict[str, Any]) -> str | None:
    version = p.get("version")
    return version if isinstance(version, str) and version else None


def _entrada(
    p: dict[str, Any],
    i: int,
    fichero: str,
    lineas: list[int],
    ficheros: list[tuple[str, str]],
    fuera: str,
    blando: str,
) -> Fijado:
    """`fuera`: no se puede comprobar nunca (git, ruta…). `blando`: otro índice o espejo,
    que se comprueba contra PyPI si hay sha256 y se salta si no."""
    via = ""
    if not fuera and blando:
        if ficheros:
            via = blando
        else:
            fuera = f"{blando} (no sha256 locked to match against PyPI)"
    version = _version(p)
    return Fijado(
        nombre=_nombre(p, i),
        version=version,
        lockfile=fichero,
        linea=lineas[i] if i < len(lineas) else 0,
        ficheros=tuple(ficheros),
        fuera_de_pypi=fuera,
        via=via,
        sin_fijar="" if version else "no version in the lockfile",
    )


# --- pylock.toml (PEP 751) -----------------------------------------------------------------


def _pylock(datos: dict[str, Any], texto: str, fichero: str) -> list[Fijado]:
    version = datos.get("lock-version")
    if not isinstance(version, str) or version.split(".")[0] != "1":
        raise Ilegible(f"unsupported lock-version {version!r} (this release reads 1.x)")
    paquetes = _lista(datos, "packages", "[[packages]]")
    lineas = _lineas(texto, "packages")
    fijados = []
    for i, p in enumerate(paquetes):
        fuera = next((f"{k} source" for k in ("vcs", "directory") if k in p), "")
        blando = ""
        archivo = p.get("archive")
        indice = p.get("index")
        if isinstance(indice, str) and not _es_pypi(indice):
            blando = f"index {indice}"
        sdist = p.get("sdist")
        ruedas = p.get("wheels", [])
        dists = ([sdist] if isinstance(sdist, dict) else []) + (
            [w for w in ruedas if isinstance(w, dict)] if isinstance(ruedas, list) else []
        )
        if isinstance(archivo, dict):
            if isinstance(archivo.get("url"), str):
                dists.append(archivo)
                blando = blando or f"archive {archivo['url']}"
            else:
                fuera = fuera or "archive source"
        ficheros = []
        for d in dists:
            url = d.get("url")
            if not blando and isinstance(url, str) and _host(url) not in _HOSTS_PYPI:
                blando = f"files from {_host(url) or url}"
            if not fuera and not isinstance(url, str) and isinstance(d.get("path"), str):
                fuera = "local file"
            nombre_f = d.get("name") or _nombre_de_url(str(url or d.get("path") or ""))
            hashes = d.get("hashes")
            sha = hashes.get("sha256") if isinstance(hashes, dict) else None
            if nombre_f and isinstance(sha, str):
                ficheros.append((str(nombre_f), sha.lower()))
        fijados.append(_entrada(p, i, fichero, lineas, ficheros, fuera, blando))
    return fijados


# --- uv.lock -----------------------------------------------------------------------------


def _uv(datos: dict[str, Any], texto: str, fichero: str) -> list[Fijado]:
    if datos.get("version") != 1:
        raise Ilegible(
            f"unsupported uv.lock version {datos.get('version')!r} (this release reads version 1)"
        )
    paquetes = _lista(datos, "package", "[[package]]")
    lineas = _lineas(texto, "package")
    fijados = []
    for i, p in enumerate(paquetes):
        origen = p.get("source")
        if not isinstance(origen, dict) or not origen:
            raise Ilegible(f"entry #{i + 1} has no source")
        if "virtual" in origen or "editable" in origen:
            continue  # el propio proyecto (o uno local editable): no viene de ningún índice
        fuera = blando = ""
        if "registry" in origen:
            if not _es_pypi(str(origen["registry"])):
                blando = f"registry {origen['registry']}"
        elif "url" in origen:
            blando = f"URL {origen['url']}"
        else:
            fuera = f"{next(iter(origen))} source"
        ficheros = []
        ruedas = p.get("wheels", [])
        dists = ([p["sdist"]] if isinstance(p.get("sdist"), dict) else []) + (
            [w for w in ruedas if isinstance(w, dict)] if isinstance(ruedas, list) else []
        )
        for d in dists:
            sha = _sha256(d.get("hash"))
            if isinstance(d.get("url"), str) and sha:
                ficheros.append((_nombre_de_url(d["url"]), sha))
        fijados.append(_entrada(p, i, fichero, lineas, ficheros, fuera, blando))
    return fijados


# --- poetry.lock ---------------------------------------------------------------------------


def _poetry(datos: dict[str, Any], texto: str, fichero: str) -> list[Fijado]:
    meta = datos.get("metadata", {})
    version_lock = str(meta.get("lock-version", "")) if isinstance(meta, dict) else ""
    if version_lock.split(".")[0] not in ("1", "2"):
        raise Ilegible(
            f"unsupported poetry.lock lock-version {version_lock or None!r} "
            "(this release reads 1.x and 2.x)"
        )
    # lock-version 1.x guarda los ficheros aparte, en [metadata.files]; 2.x, en cada paquete.
    ficheros_meta = meta.get("files", {}) if isinstance(meta, dict) else {}
    paquetes = _lista(datos, "package", "[[package]]")
    lineas = _lineas(texto, "package")
    fijados = []
    for i, p in enumerate(paquetes):
        fuera = blando = ""
        origen = p.get("source")
        if isinstance(origen, dict):
            tipo, url = origen.get("type", ""), str(origen.get("url", ""))
            if tipo == "legacy":
                if not _es_pypi(url):
                    blando = f"index {url}"
            elif tipo == "url":
                blando = f"URL {url}"
            else:
                fuera = f"{tipo} source {url}".strip()
        lista = p.get("files")
        if lista is None and isinstance(ficheros_meta, dict):
            lista = ficheros_meta.get(p.get("name", ""), [])
        ficheros = []
        for f in lista if isinstance(lista, list) else []:
            sha = _sha256(f.get("hash")) if isinstance(f, dict) else None
            if sha and isinstance(f.get("file"), str):
                ficheros.append((f["file"], sha))
        fijados.append(_entrada(p, i, fichero, lineas, ficheros, fuera, blando))
    return fijados


# --- requirements.txt ----------------------------------------------------------------------
# El preprocesado es el de pip 26 (pip/_internal/req/req_file.py: join_lines,
# ignore_comments, expand_env_variables), con sus mismas expresiones regulares.

_COMENTARIO = re.compile(r"(^|\s+)#.*$")
_VARIABLE = re.compile(r"(?P<var>\$\{(?P<name>[A-Z0-9_]+)\})")
_HASH = re.compile(r"--hash[=\s]+(\w+):([0-9a-fA-F]+)")
_INCLUYE = {"-r", "--requirement"}
_RESTRICCION = {"-c", "--constraint"}
_INDICE = {"-i", "--index-url"}
_OTROS_ORIGENES = {"--extra-index-url", "-f", "--find-links"}
_EDITABLE = {"-e", "--editable"}


def _preprocesa(texto: str) -> list[tuple[int, str]]:
    unidas: list[tuple[int, str]] = []
    primera, nueva = 0, list[str]()
    for n, linea in enumerate(texto.splitlines(), 1):
        if not linea.endswith("\\") or _COMENTARIO.match(linea):
            if _COMENTARIO.match(linea):
                linea = " " + linea
            if nueva:
                nueva.append(linea)
                unidas.append((primera, "".join(nueva)))
                nueva = []
            else:
                unidas.append((n, linea))
        else:
            if not nueva:
                primera = n
            nueva.append(linea.strip("\\"))
    if nueva:
        unidas.append((primera, "".join(nueva)))
    salida = []
    for n, linea in unidas:
        linea = _COMENTARIO.sub("", linea).strip()
        if not linea:
            continue
        for variable, nombre in _VARIABLE.findall(linea):
            valor = os.getenv(nombre)
            if valor:
                linea = linea.replace(variable, valor)
        salida.append((n, linea))
    return salida


@dataclass
class _Estado:
    lectura: Lectura = field(default_factory=Lectura)
    visitados: set[Path] = field(default_factory=set)
    indice: str = ""
    """`--index-url` distinto de PyPI, o `--no-index`: pip no instala desde PyPI."""


def _requirements(ruta: Path) -> Lectura:
    estado = _Estado()
    _lee_requirements(ruta, estado)
    lectura = estado.lectura
    if estado.indice:
        # Como en pip, las opciones de índice valen para todo el fichero (y sus -r).
        lectura.fijados = [
            f
            if f.fuera_de_pypi or not f.version
            else (
                replace(f, via=estado.indice)
                if f.tiene_sha256
                else replace(f, fuera_de_pypi=f"{estado.indice} (no --hash to match against PyPI)")
            )
            for f in lectura.fijados
        ]
    return lectura


def _opcion(linea: str) -> tuple[str, str]:
    """`--opcion=valor`, `--opcion valor`, `-xvalor` o `-x valor` → (opción, valor)."""
    if linea.startswith("--"):
        partes = re.split(r"[\s=]+", linea, maxsplit=1)
        return partes[0], partes[1].strip() if len(partes) > 1 else ""
    return linea[:2], linea[2:].strip()


def _lee_requirements(ruta: Path, estado: _Estado) -> None:
    estado.visitados.add(ruta.resolve())
    fichero = str(ruta)
    texto = ruta.read_text(encoding="utf-8-sig")
    lectura = estado.lectura

    def nota(regla: str, detalle: str, n: int) -> None:
        lectura.hallazgos.append(REGLAS[regla].hallazgo(detalle, fichero=fichero, linea=n))
        if regla == "LOCK-001":
            lectura.ilegible = True

    for n, linea in _preprocesa(texto):
        if linea.startswith("-"):
            opcion, valor = _opcion(linea)
            if opcion in _INCLUYE:
                _incluye(ruta, valor, n, estado)
            elif opcion in _RESTRICCION:
                pass  # un fichero de restricciones no instala nada: no se comprueba
            elif opcion in _EDITABLE:
                lectura.fijados.append(
                    Fijado(valor, None, fichero, n, fuera_de_pypi="editable install")
                )
            elif opcion == "--no-index" or (opcion in _INDICE and not _es_pypi(valor)):
                estado.indice = "--no-index" if opcion == "--no-index" else f"index {valor}"
                nota(
                    "SRC-003",
                    f"`{linea}`: pip does not install from pypi.org. Entries with --hash are "
                    "still checked against PyPI by sha256; entries without one are skipped.",
                    n,
                )
            elif opcion in _OTROS_ORIGENES:
                nota(
                    "SRC-003",
                    f"`{opcion} {valor}`: pip may install from there, but attest-lint "
                    "only knows the attestation history on pypi.org.",
                    n,
                )
            continue
        sin_expandir = _VARIABLE.search(linea)
        if sin_expandir:
            nota(
                "LOCK-001",
                f"`{sin_expandir.group('var')}` is not set in this environment, so this line "
                "cannot be resolved (pip expands ${VAR} from the environment).",
                n,
            )
            continue
        hashes = frozenset(h.lower() for alg, h in _HASH.findall(linea) if alg.lower() == "sha256")
        requisito = _HASH.sub("", linea).split(" --", 1)[0].strip()
        if re.match(r"^(\.|/|~|[A-Za-z]:[\\/])", requisito) or re.match(
            r"^\w[\w+.-]*://", requisito
        ):
            lectura.fijados.append(Fijado(requisito, None, fichero, n, fuera_de_pypi="path or URL"))
            continue
        try:
            r = Requirement(requisito)
        except InvalidRequirement as exc:
            nota("LOCK-001", f"Invalid requirement: {exc}", n)
            continue
        nombre = canonicalize_name(r.name)
        if r.url:
            lectura.fijados.append(Fijado(nombre, None, fichero, n, fuera_de_pypi=f"URL {r.url}"))
            continue
        # Fijada = un `==` (sin comodín) o `===` que satisface el resto de especificadores.
        exactos = [
            e.version
            for e in r.specifier
            if e.operator == "===" or (e.operator == "==" and "*" not in e.version)
        ]
        version = exactos[0] if len(exactos) == 1 else None
        if version and len(r.specifier) > 1:
            try:
                if not r.specifier.contains(version, prereleases=True):
                    version = None
            except ValueError:
                version = None
        lectura.fijados.append(
            Fijado(
                nombre,
                version,
                fichero,
                n,
                hashes=hashes,
                sin_fijar="" if version else (str(r.specifier) or "no version specifier"),
            )
        )


def _incluye(ruta: Path, valor: str, n: int, estado: _Estado) -> None:
    fichero = str(ruta)
    lectura = estado.lectura

    def falla(detalle: str) -> None:
        lectura.hallazgos.append(REGLAS["LOCK-001"].hallazgo(detalle, fichero=fichero, linea=n))
        lectura.ilegible = True

    if not valor or re.match(r"^\w[\w+.-]*://", valor):
        falla(f"Included file `{valor}` cannot be followed (remote or empty).")
        return
    destino = ruta.parent / valor
    if destino.resolve() in estado.visitados:
        return  # inclusión circular: pip la rechazaría; aquí basta con no repetirla
    try:
        _lee_requirements(destino, estado)
    except OSError as exc:
        falla(f"Included file `{valor}`: {exc.strerror or exc}.")
    except UnicodeDecodeError:
        falla(f"Included file `{valor}` is not valid UTF-8.")

"""Las reglas AT-001…AT-005 sobre el historial de un paquete en PyPI.

**El historial se ordena por fecha de subida, no por número de versión.** La pregunta es
«¿dejó de publicarse con atestación?», y eso es una pregunta sobre el tiempo: una 1.2.9
de mantenimiento subida después de la 2.0.0 viene del pipeline que había *entonces*. La
fecha de una versión es la del primer fichero que se subió de ella (`upload-time`,
PEP 700). Las versiones retiradas (*yanked*) cuentan: siguen en el índice y dicen qué
pipeline tenía el proyecto.

**Las prerreleases no cuentan como historial de una versión estable**, como hace pnpm
en su `trustPolicy` desde la v10.24.0, «so a trusted prerelease cannot block a stable
release that lacks trust evidence».

**Versión contra versión, fichero contra fichero del mismo tipo.** AT-001 compara
versiones enteras: una versión está atestada si lo está cualquiera de sus ficheros, la
fijada igual que las anteriores. Que la versión esté atestada pero los ficheros que fija
el lockfile no (un proyecto que sólo atesta el sdist y un lock que fija la wheel) es
otra cosa, AT-005, y no una regresión. AT-002 compara un sdist con un sdist y una wheel
con una wheel de las mismas etiquetas: el sdist y las wheels salen a menudo de
workflows distintos, y compararlos entre sí inventaría un cambio de publicador.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from packaging.tags import sys_tags
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from attest_lint.catalogo import REGLAS
from attest_lint.hallazgos import Hallazgo, Severidad
from attest_lint.lockfiles import Fijado
from attest_lint.pypi import Cliente, ErrorDeRed
from attest_lint.verificacion import FALLIDA, INDETERMINADA

Verificador = Callable[[dict[str, Any], str, str, bool], tuple[str, str]]

AVISO_REGRESION = (
    "A regression is not proof of compromise: a new CI pipeline, a manual upload or a "
    "pre-release built elsewhere look the same from the index. Check the project's "
    "release notes or workflow before trusting this release, or allowlist it."
)
_PERMITIBLES = {"AT-001", "AT-002", "AT-003", "AT-005"}
MAX_VERIFICAR = 10
"""Ficheros verificados por versión con --verify (una petición a PyPI por fichero)."""


@dataclass(frozen=True)
class Fichero:
    nombre: str
    sha256: str
    procedencia: str | None
    subido: str
    retirado: bool = False

    @property
    def clase(self) -> tuple[str, frozenset[str]]:
        """("sdist", ∅) o ("wheel", etiquetas): para comparar ficheros del mismo tipo."""
        if self.nombre.endswith(".whl"):
            try:
                return "wheel", frozenset(str(t) for t in parse_wheel_filename(self.nombre)[3])
            except InvalidWheelFilename:
                return "wheel", frozenset()
        return "sdist", frozenset()


@dataclass
class Publicacion:
    """Una versión publicada: sus ficheros y la fecha del primero que se subió."""

    texto: str
    clave: Version
    subida: str = ""
    ficheros: list[Fichero] = field(default_factory=list)

    @property
    def atestada(self) -> bool:
        return any(f.procedencia for f in self.ficheros)

    @property
    def retirada(self) -> bool:
        return bool(self.ficheros) and all(f.retirado for f in self.ficheros)


@dataclass
class Opciones:
    ventana: int = 0
    """Cuántas versiones previas mirar en AT-001; 0 = todas."""
    permitidos: list[tuple[str, Version | None]] = field(default_factory=list)
    estricto: bool = False
    verificar: bool = False
    max_verificar: int = MAX_VERIFICAR
    """Tope de ficheros verificados por versión; 0 = sin tope."""

    def permite(self, nombre: str, version: Version) -> bool:
        return any(n == nombre and (v is None or v == version) for n, v in self.permitidos)


def permitido(texto: str) -> tuple[str, Version | None]:
    """`nombre` o `nombre==versión` → (nombre normalizado, versión o None)."""
    nombre, sep, version = texto.strip().partition("==")
    if not nombre.strip():
        raise ValueError(f"invalid allowlist entry: {texto!r}")
    try:
        return canonicalize_name(nombre.strip()), Version(version.strip()) if sep else None
    except InvalidVersion as exc:
        raise ValueError(f"invalid allowlist entry: {texto!r}") from exc


def historial(indice: dict[str, Any]) -> list[Publicacion]:
    """Las versiones del índice en orden de subida (las que no tienen ficheros, fuera)."""
    por_version: dict[Version, Publicacion] = {}
    for f in indice.get("files", []):
        if not isinstance(f, dict) or not isinstance(f.get("filename"), str):
            continue
        nombre = f["filename"]
        try:
            if nombre.endswith(".whl"):
                version = parse_wheel_filename(nombre)[1]
            elif nombre.endswith((".tar.gz", ".zip")):
                version = parse_sdist_filename(nombre)[1]
            else:
                continue  # .egg, .exe, .tar.bz2…: formatos que PyPI ya no admite
        except (InvalidWheelFilename, InvalidSdistFilename, InvalidVersion):
            continue
        hashes = f.get("hashes")
        digest = hashes.get("sha256", "") if isinstance(hashes, dict) else ""
        procedencia = f.get("provenance")
        fichero = Fichero(
            nombre=nombre,
            sha256=str(digest).lower(),
            procedencia=procedencia if isinstance(procedencia, str) and procedencia else None,
            subido=str(f.get("upload-time") or ""),
            retirado=bool(f.get("yanked")),
        )
        pub = por_version.setdefault(version, Publicacion(str(version), version))
        pub.ficheros.append(fichero)
        if fichero.subido and (not pub.subida or fichero.subido < pub.subida):
            pub.subida = fichero.subido
    return sorted(por_version.values(), key=lambda p: (p.subida, p.clave))


def _identidades(procedencia: dict[str, Any]) -> list[tuple[tuple[str, str], ...]]:
    """La identidad de cada bundle: el `publisher` sin `claims` (que son de cada ejecución)."""
    salida = []
    for paquete in procedencia.get("attestation_bundles", []):
        editor = paquete.get("publisher") if isinstance(paquete, dict) else None
        if not isinstance(editor, dict):
            continue
        campos = []
        for clave, valor in editor.items():
            if clave == "claims":
                continue
            texto = "" if valor is None else str(valor)
            # GitHub y GitLab no distinguen mayúsculas en owner/repo.
            campos.append((clave, texto.casefold() if clave == "repository" else texto))
        salida.append(tuple(sorted(campos)))
    return salida


def _describe(identidad: tuple[tuple[str, str], ...]) -> str:
    campos = dict(identidad)
    resto = " ".join(f"{k}={v}" for k, v in identidad if k != "kind" and v)
    return f"{campos.get('kind', '?')} {resto}".strip()


def _orden(f: Fichero) -> tuple[int, str]:
    """El sdist primero, luego las wheels por nombre: siempre el mismo fichero."""
    return (0 if f.clase[0] == "sdist" else 1), f.nombre


def _pareja(actuales: list[Fichero], previos: list[Fichero]) -> tuple[Fichero, Fichero] | None:
    """Un fichero atestado de cada versión, del mismo tipo: mismas etiquetas de wheel si
    las hay, si no sdist con sdist o wheel con wheel. None si no hay nada comparable."""
    actuales = sorted((f for f in actuales if f.procedencia), key=_orden)
    previos = sorted((f for f in previos if f.procedencia), key=_orden)
    for a in actuales:  # primero, las mismas etiquetas
        for b in previos:
            if a.clase == b.clase:
                return a, b
    for a in actuales:  # si no, el mismo tipo
        for b in previos:
            if a.clase[0] == b.clase[0]:
                return a, b
    return None


def _fecha(p: Publicacion) -> str:
    return (p.subida[:10] or "unknown date") + (", yanked" if p.retirada else "")


def analiza(
    fijado: Fijado,
    cliente: Cliente,
    opciones: Opciones,
    verificador: Verificador | None = None,
) -> tuple[list[Hallazgo], dict[str, Any], bool]:
    """(hallazgos, resumen del paquete, suprimido por la allowlist)."""
    etiqueta = f"{fijado.nombre} {fijado.version}" if fijado.version else fijado.nombre
    donde: dict[str, Any] = {
        "fichero": fijado.lockfile,
        "linea": fijado.linea,
        "paquete": etiqueta,
    }
    resumen: dict[str, Any] = {
        "name": fijado.nombre,
        "version": fijado.version,
        "lockfile": fijado.lockfile,
        "line": fijado.linea,
        "checked": False,
    }
    if fijado.via:
        resumen["locked_from"] = fijado.via
    if fijado.fuera_de_pypi:
        detalle = f"Installed from {fijado.fuera_de_pypi}; attest-lint only checks pypi.org."
        return [REGLAS["SRC-001"].hallazgo(detalle, **donde)], resumen, False
    if not fijado.version:
        detalle = (
            f"`{fijado.sin_fijar}`: the release that gets installed can change, so there is "
            "no single release to compare with its history. Pin it with a lockfile "
            "(uv lock, poetry lock, pip-compile, pip lock)."
        )
        return [REGLAS["LOCK-002"].hallazgo(detalle, **donde)], resumen, False
    try:
        fijada = Version(fijado.version)
    except InvalidVersion:
        detalle = f"`{fijado.version}` is not a valid version (PEP 440)."
        return [REGLAS["LOCK-002"].hallazgo(detalle, **donde)], resumen, False
    if fijada.local:
        detalle = (
            f"`+{fijada.local}` is a local version label, and PyPI rejects uploads with one "
            f"(“The use of local versions in '{fijada}' is not allowed”): this release comes "
            "from another index."
        )
        return [REGLAS["SRC-001"].hallazgo(detalle, **donde)], resumen, False
    try:
        hallazgos = _analiza(fijado, fijada, cliente, opciones, verificador, donde, resumen)
    except ErrorDeRed as exc:
        return [REGLAS["NET-001"].hallazgo(f"{exc}.", **donde)], resumen, False
    if not opciones.permite(fijado.nombre, fijada):
        return hallazgos, resumen, False
    # La allowlist es «ya lo he revisado»: calla las señales sobre el historial, nunca una
    # firma que no verifica (AT-004) ni un problema de lectura.
    quedan = [h for h in hallazgos if h.regla not in _PERMITIBLES]
    return quedan, resumen, len(quedan) != len(hallazgos)


def _analiza(
    fijado: Fijado,
    fijada: Version,
    cliente: Cliente,
    opciones: Opciones,
    verificador: Verificador | None,
    donde: dict[str, Any],
    resumen: dict[str, Any],
) -> list[Hallazgo]:
    hallazgos: list[Hallazgo] = []
    etiqueta = donde["paquete"]
    indice = cliente.indice(fijado.nombre)
    if indice is None:
        detalle = "PyPI has no project with this name (404): it comes from another index."
        return [REGLAS["SRC-001"].hallazgo(detalle, **donde)]
    versiones = historial(indice)
    actual = next((v for v in versiones if v.clave == fijada), None)
    if actual is None and not cliente.offline:
        # La caché puede ser anterior a la publicación que el lockfile acaba de fijar.
        indice = cliente.indice(fijado.nombre, fresco=True) or indice
        versiones = historial(indice)
        actual = next((v for v in versiones if v.clave == fijada), None)
    if actual is None:
        detalle = (
            f"PyPI serves no wheel or sdist for {etiqueta}: it was deleted, it only has "
            "legacy files (.egg, .exe), or the lockfile points at another index that hosts "
            "a project with the same name."
        )
        return [REGLAS["SRC-002"].hallazgo(detalle, **donde)]

    considerados, digest_propio, problemas = _ficheros(fijado, actual)
    hallazgos += [REGLAS["SRC-002"].hallazgo(p, **donde) for p in problemas]

    posicion = versiones.index(actual)
    previas = versiones[:posicion]
    if not fijada.is_prerelease:
        previas = [v for v in previas if not v.clave.is_prerelease]
    ventana = previas[-opciones.ventana :] if opciones.ventana else previas
    ultima_previa = next((v for v in reversed(previas) if v.atestada), None)
    resumen.update(
        checked=True,
        attested=actual.atestada,
        previous_releases=len(previas),
        last_attested_before=ultima_previa.texto if ultima_previa else None,
    )

    if not actual.atestada:
        en_ventana = [v for v in ventana if v.atestada]
        nunca = not any(v.atestada for v in versiones)
        if en_ventana:
            ultima = en_ventana[-1]
            desde = len(previas) - previas.index(ultima)  # las de después, y ésta
            ambito = f"the last {len(ventana)}" if opciones.ventana else f"the {len(ventana)}"
            ambito += " earlier" if fijada.is_prerelease else " earlier final"
            detalle = (
                f"PyPI serves no PEP 740 attestation for any file of {etiqueta}, but "
                f"{len(en_ventana)} of {ambito} releases have one. Last attested: "
                f"{ultima.texto} ({_fecha(ultima)}); {desde} release(s) without attestation "
                "since then, this one included."
            )
            if fijada.is_prerelease:
                detalle += " This is a pre-release."
            hallazgos.append(REGLAS["AT-001"].hallazgo(f"{detalle}\n{AVISO_REGRESION}", **donde))
        elif nunca:
            detalle = (
                f"None of the {len(versiones)} releases of {fijado.nombre} on PyPI carries a "
                "PEP 740 attestation, so there is no history to compare against. Many "
                "projects have not adopted Trusted Publishing yet."
            )
            hallazgos.append(REGLAS["AT-003"].hallazgo(detalle, **donde))
        return hallazgos

    atestados = [f for f in considerados if f.procedencia]
    if not atestados:
        # Sólo puede pasar si el lockfile fija ficheros: la versión sí está atestada.
        con = [f.nombre for f in actual.ficheros if f.procedencia]
        fijados = sorted(f.nombre for f in considerados)
        detalle = (
            f"PyPI serves PEP 740 attestations for {len(con)} of the {len(actual.ficheros)} "
            f"files of {etiqueta} ({', '.join(sorted(con)[:3])}{', …' if len(con) > 3 else ''}"
            f"), but none for the {len(fijados)} file(s) your lockfile pins "
            f"({', '.join(fijados[:3])}{', …' if len(fijados) > 3 else ''}). What you install "
            "cannot be tied to a publisher. This is how the project publishes, not a "
            "regression."
        )
        hallazgos.append(REGLAS["AT-005"].hallazgo(detalle, **donde))
        return hallazgos

    if ultima_previa is not None:
        pareja = _pareja(atestados, ultima_previa.ficheros) or _pareja(
            [f for f in actual.ficheros if f.procedencia], ultima_previa.ficheros
        )
        if pareja is None:
            resumen["publisher_compared"] = False
        else:
            hallazgos += _compara_editores(pareja, ultima_previa, cliente, opciones, donde, resumen)

    if opciones.verificar and verificador is not None:
        hallazgos += _verifica(
            atestados, digest_propio, cliente, verificador, opciones, donde, resumen
        )
    return hallazgos


def _compara_editores(
    pareja: tuple[Fichero, Fichero],
    ultima_previa: Publicacion,
    cliente: Cliente,
    opciones: Opciones,
    donde: dict[str, Any],
    resumen: dict[str, Any],
) -> list[Hallazgo]:
    actual_f, previo_f = pareja
    ahora = _identidades(cliente.procedencia(actual_f.procedencia or ""))
    antes = _identidades(cliente.procedencia(previo_f.procedencia or ""))
    resumen["publisher"] = [_describe(i) for i in ahora]
    resumen["publisher_compared"] = [actual_f.nombre, previo_f.nombre]
    # Un bundle añadido por un tercero (PEP 740 lo permite) no es un cambio de publicador;
    # sólo lo es no tener ninguna identidad en común.
    if not ahora or not antes or set(ahora) & set(antes):
        return []
    cambios = sorted(
        {k for k, _ in ahora[0]} ^ {k for k, _ in antes[0]}
        | {k for k, v in ahora[0] if dict(antes[0]).get(k) != v}
    )
    detalle = (
        f"{actual_f.nombre} was published by {_describe(ahora[0])}; {previo_f.nombre}, from "
        f"the last attested release before it ({ultima_previa.texto}, "
        f"{_fecha(ultima_previa)}), by {_describe(antes[0])}. Changed: {', '.join(cambios)}.\n"
        "Legitimate causes exist (repository renamed or transferred, workflow renamed, "
        "deployment environment added); confirm with the project before trusting the new "
        "publisher."
    )
    severidad = Severidad.ERROR if opciones.estricto else None
    return [REGLAS["AT-002"].hallazgo(detalle, severidad=severidad, **donde)]


def _ficheros(
    fijado: Fijado, actual: Publicacion
) -> tuple[list[Fichero], dict[str, str], list[str]]:
    """Los ficheros que cuentan, el sha256 que fija el lockfile para cada uno y los problemas."""
    problemas: list[str] = []
    propios: dict[str, str] = {}
    considerados: list[Fichero] = []
    origen = f" (locked from {fijado.via})" if fijado.via else ""
    if fijado.ficheros:
        # Primero por sha256 (es el fichero, se llame como se llame), luego por identidad
        # del nombre: uv escribe en pylock `zope_interface-7.2-….whl` para el fichero que
        # PyPI sirve como `zope.interface-7.2-….whl`.
        por_sha = {f.sha256: f for f in actual.ficheros if f.sha256}
        por_nombre = {_identidad(f.nombre): f for f in actual.ficheros}
        for nombre, sha in fijado.ficheros:
            f = por_sha.get(sha) or por_nombre.get(_identidad(nombre))
            if f is None:
                problemas.append(f"The locked file {nombre}{origen} is not on PyPI.")
            elif f.sha256 and f.sha256 != sha:
                problemas.append(
                    f"The sha256 locked for {nombre}{origen} differs from the one PyPI serves: "
                    "the locked file is not PyPI's, or one of them was altered."
                )
            else:
                considerados.append(f)
                propios[f.nombre] = sha
    elif fijado.hashes:
        considerados = [f for f in actual.ficheros if f.sha256 in fijado.hashes]
        propios = {f.nombre: f.sha256 for f in considerados}
        if not considerados:
            problemas.append(
                f"None of the --hash values{origen} matches a file PyPI serves for it."
            )
    if not considerados:
        considerados = list(actual.ficheros)
    return considerados, propios, problemas


def _identidad(nombre: str) -> tuple[object, ...]:
    """Lo que identifica un fichero de distribución más allá de cómo se escriba su nombre."""
    try:
        if nombre.endswith(".whl"):
            proyecto, version, build, tags = parse_wheel_filename(nombre)
            return "wheel", proyecto, version, build, tags
        if nombre.endswith((".tar.gz", ".zip")):
            return ("sdist", *parse_sdist_filename(nombre))
    except (InvalidWheelFilename, InvalidSdistFilename, InvalidVersion):
        pass
    return ("other", nombre.lower())


def _para_verificar(atestados: list[Fichero], tope: int) -> tuple[list[Fichero], int]:
    """Primero las wheels que se instalarían en esta plataforma, luego el sdist, luego el
    resto; como mucho `tope` (0 = todos). Devuelve también cuántos quedan fuera."""
    etiquetas = {str(t): i for i, t in enumerate(sys_tags())}

    def prioridad(f: Fichero) -> tuple[int, int, str]:
        clase, tags = f.clase
        if clase == "wheel" and tags & etiquetas.keys():
            return 0, min(etiquetas[t] for t in tags if t in etiquetas), f.nombre
        return (1 if clase == "sdist" else 2), 0, f.nombre

    orden = sorted(atestados, key=prioridad)
    elegidos = orden[:tope] if tope else orden
    return elegidos, len(orden) - len(elegidos)


def _verifica(
    atestados: list[Fichero],
    propios: dict[str, str],
    cliente: Cliente,
    verificador: Verificador,
    opciones: Opciones,
    donde: dict[str, Any],
    resumen: dict[str, Any],
) -> list[Hallazgo]:
    hallazgos = []
    verificados = 0
    elegidos, fuera = _para_verificar(atestados, opciones.max_verificar)
    for f in elegidos:
        procedencia = cliente.procedencia(f.procedencia or "")
        digest = propios.get(f.nombre) or f.sha256
        origen = "your lockfile" if f.nombre in propios else "PyPI (not locked)"
        resultado, explicacion = verificador(procedencia, f.nombre, digest, cliente.offline)
        if resultado == FALLIDA:
            hallazgos.append(
                REGLAS["AT-004"].hallazgo(
                    f"{f.nombre} (sha256 from {origen}): {explicacion}", **donde
                )
            )
        elif resultado == INDETERMINADA:
            hallazgos.append(
                REGLAS["AT-004"].hallazgo(
                    f"{f.nombre}: could not be verified: {explicacion}",
                    severidad=Severidad.INCOMPLETO,
                    **donde,
                )
            )
        else:
            verificados += 1
    resumen["verified_files"] = verificados
    if fuera:
        resumen["not_verified_files"] = fuera
    return hallazgos

"""La interfaz de línea de comandos (en inglés: es para un público global).

**El código de salida es la parte que importa.** `1` cuando hay errores, `0` cuando no,
`2` cuando la herramienta no ha podido hacer su trabajo: un lockfile ilegible, un dato
de PyPI que no llegó, `--verify` sin la librería. Un informe verde sobre la mitad de las
dependencias sería peor que ninguno.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from attest_lint import __version__
from attest_lint.hallazgos import Hallazgo, Informe, Severidad
from attest_lint.lockfiles import TIPOS, Fijado, lee
from attest_lint.pypi import (
    TTL_INDICE,
    Cache,
    Cliente,
    Transporte,
    cache_por_defecto,
    transporte_http,
)
from attest_lint.reglas import MAX_VERIFICAR, Opciones, Verificador, analiza, permitido
from attest_lint.salida import como_json, como_sarif, texto

PREDETERMINADOS = ("pylock.toml", "uv.lock", "poetry.lock", "requirements.txt")

EPILOGO = """\
attest-lint reads a lockfile and compares every pinned PyPI release with that
package's own history on PyPI:

  AT-001  error    earlier releases had PEP 740 attestations, the pinned one has none
  AT-002  warning  the Trusted Publisher (repository, workflow, environment) changed
                   since the last attested release (error with --strict)
  AT-003  info     the package has never published attestations
  AT-004  error    the attestation does not verify (only with --verify)
  AT-005  warning  the release is attested, but not the files the lockfile pins

A regression is a signal to review, not proof of compromise: a new CI pipeline, a
manual upload or a pre-release look the same from the index.

Exit codes: 0 no errors; 1 errors (or warnings with --strict); 2 the tool could not do
its job (unreadable lockfile, PyPI data missing, an attestation that --verify could
not check, --verify without pypi-attestations, or nothing pinned to check).
"""


def _argumentos(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="attest-lint",
        description="Flag pinned PyPI dependencies whose attestations regressed.",
        epilog=EPILOGO,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "lockfiles",
        nargs="*",
        type=Path,
        help="pylock.toml, uv.lock, poetry.lock or requirements.txt "
        f"(default: the first of {', '.join(PREDETERMINADOS)} found here)",
    )
    p.add_argument("--type", choices=TIPOS, help="force the lockfile format")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--strict", action="store_true", help="AT-002 becomes an error; warnings exit 1")
    p.add_argument(
        "--window",
        type=int,
        default=0,
        metavar="N",
        help="AT-001 looks at the N releases before the pinned one (default 0: all)",
    )
    p.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="NAME[==VERSION]",
        help="do not report this package (or release); repeatable",
    )
    p.add_argument(
        "--allowlist",
        type=Path,
        metavar="FILE",
        help="file with one NAME or NAME==VERSION per line ('#' starts a comment)",
    )
    p.add_argument(
        "--verify",
        action="store_true",
        help="verify attestations cryptographically (needs attest-lint[verify])",
    )
    p.add_argument(
        "--verify-max-files",
        type=int,
        default=MAX_VERIFICAR,
        metavar="N",
        help="with --verify, verify at most N files per release, wheels for this platform "
        f"first (one PyPI request each; default {MAX_VERIFICAR}, 0 = all)",
    )
    p.add_argument(
        "--offline", action="store_true", help="use only the cache; never go to the network"
    )
    p.add_argument("--cache-dir", type=Path, metavar="DIR", help="default: the user cache dir")
    p.add_argument(
        "--cache-ttl",
        type=int,
        default=TTL_INDICE,
        metavar="SECONDS",
        help=f"how long a cached project index is fresh (default {TTL_INDICE})",
    )
    p.add_argument("--no-cache", action="store_true", help="neither read nor write the cache")
    p.add_argument("--no-color", action="store_true", help="disable colour")
    p.add_argument("--version", action="version", version=f"attest-lint {__version__}")
    return p.parse_args(argv)


def _error(msg: str) -> int:
    print(f"attest-lint: {msg}", file=sys.stderr)
    return 2


def _salida_utf8() -> None:
    # On Windows, redirected output (CI logs, pipes, files) uses the ANSI code page: print()
    # could raise UnicodeEncodeError on '·' and the tool would exit 2 on a valid run.
    for flujo in (sys.stdout, sys.stderr):
        reconfigurar = getattr(flujo, "reconfigure", None)
        if reconfigurar is not None:
            try:
                reconfigurar(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(
    argv: list[str] | None = None,
    transporte: Transporte | None = None,
    verificador: Verificador | None = None,
) -> int:
    """`transporte` y `verificador` sólo los cambian los tests (respuestas grabadas)."""
    _salida_utf8()
    args = _argumentos(argv)
    try:
        return _ejecuta(args, transporte, verificador)
    except Exception as exc:  # red de seguridad: nunca una traza en CI
        return _error(f"internal error: {type(exc).__name__}: {exc}".splitlines()[0])


def _permitidos(args: argparse.Namespace) -> list[str]:
    entradas = list(args.allow)
    if args.allowlist is not None:
        contenido = args.allowlist.read_text(encoding="utf-8-sig")
        for linea in contenido.splitlines():
            linea = linea.split("#", 1)[0].strip()
            if linea:
                entradas.append(linea)
    return entradas


def _ejecuta(
    args: argparse.Namespace, transporte: Transporte | None, verificador: Verificador | None
) -> int:
    if args.window < 0:
        return _error("--window must be 0 (all releases) or a positive number")
    if args.verify_max_files < 0:
        return _error("--verify-max-files must be 0 (all) or a positive number")
    if args.cache_ttl < 0:
        return _error("--cache-ttl must be 0 or a positive number of seconds")
    if args.offline and args.no_cache:
        return _error("--offline reads only the cache, so it cannot go with --no-cache")
    try:
        opciones = Opciones(
            ventana=args.window,
            permitidos=[permitido(e) for e in _permitidos(args)],
            estricto=args.strict,
            verificar=args.verify,
            max_verificar=args.verify_max_files,
        )
    except OSError as exc:
        return _error(f"{args.allowlist}: {exc.strerror or exc}")
    except (ValueError, UnicodeDecodeError) as exc:
        return _error(str(exc))
    if args.verify and verificador is None:
        from attest_lint import verificacion

        if not verificacion.disponible():
            return _error("--verify needs pypi-attestations: pip install 'attest-lint[verify]'")
        verificador = verificacion.verifica

    rutas: list[Path] = list(args.lockfiles)
    if not rutas:
        encontrado = next((Path(n) for n in PREDETERMINADOS if Path(n).is_file()), None)
        if encontrado is None:
            return _error(f"no lockfile given and none of {', '.join(PREDETERMINADOS)} here")
        rutas = [encontrado]

    cache = None if args.no_cache else Cache(args.cache_dir or cache_por_defecto())
    cliente = Cliente(
        transporte or transporte_http,
        cache,
        offline=args.offline,
        ttl_indice=args.cache_ttl,
    )

    hallazgos: list[Hallazgo] = []
    paquetes: list[dict[str, Any]] = []
    fijados: list[Fijado] = []
    ilegible = False
    for ruta in rutas:
        lectura = lee(ruta, args.type)
        hallazgos += lectura.hallazgos
        fijados += lectura.fijados
        ilegible = ilegible or lectura.ilegible

    suprimidos = 0
    for fijado in fijados:
        nuevos, resumen, suprimido = analiza(fijado, cliente, opciones, verificador)
        hallazgos += nuevos
        paquetes.append(resumen)
        suprimidos += suprimido

    informe = Informe(
        hallazgos=hallazgos,
        lockfiles=[str(r) for r in rutas],
        paquetes=paquetes,
        ventana=args.window,
        permitidos=suprimidos,
    )
    if args.format == "json":
        print(como_json(informe))
    elif args.format == "sarif":
        print(como_sarif(informe, __version__))
    else:
        print(texto(informe, color=not args.no_color and sys.stdout.isatty()))

    if ilegible:
        return _error("some lockfiles could not be read")
    if informe.de(Severidad.INCOMPLETO) and any(h.regla == "NET-001" for h in hallazgos):
        return _error("some PyPI data could not be retrieved")
    if args.verify and any(
        h.regla == "AT-004" and h.severidad is Severidad.INCOMPLETO for h in hallazgos
    ):
        # Con verify: true, un verde sin haber verificado sería un falso «todo bien».
        return _error("some attestations could not be verified")
    if not any(p.get("checked") for p in paquetes) and not informe.errores:
        return _error("no pinned PyPI package could be checked")
    if informe.errores or (args.strict and informe.avisos):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

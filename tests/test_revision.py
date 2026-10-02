"""Revisión adversarial del 2026-10-02: un test por punto.

Los casos sintéticos reproducen los del revisor (`syn.py`, `syn2.py`); sus lockfiles
reales (uv, pylock, poetry y requirements con todas las rarezas de pip) están copiados
sin tocar en `tests/fixtures/revision/`.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any

import pytest
import yaml

from attest_lint.lockfiles import lee
from attest_lint.pypi import (
    Cache,
    Cliente,
    ErrorDeRed,
    Respuesta,
    SinConexion,
    _SoloPyPI,
)
from tests.conftest import FIX, Grabado, ejecuta

RAIZ = FIX.parent.parent
REV = FIX / "revision"
T1, T2, T3 = "2025-01-01T00:00:00Z", "2025-02-01T00:00:00Z", "2025-03-01T00:00:00Z"


def _sha(texto: str) -> str:
    return hashlib.sha256(texto.encode()).hexdigest()


def _prov(repo: str = "org/demo", wf: str = "release.yml") -> dict[str, Any]:
    editor = {"kind": "GitHub", "repository": repo, "workflow": wf, "environment": None}
    return {"version": 1, "attestation_bundles": [{"publisher": editor, "attestations": []}]}


def _pypi(nombre: str, ficheros: list[tuple[Any, ...]]) -> Grabado:
    """ficheros: (nombre, upload-time, procedencia o None[, yanked])."""
    extra: dict[str, Any] = {}
    lista = []
    for fn, cuando, prov, *retirado in ficheros:
        url = f"https://pypi.org/integrity/{nombre}/x/{fn}/provenance" if prov else None
        if url:
            extra[url] = prov
        lista.append(
            {
                "filename": fn,
                "hashes": {"sha256": _sha(fn)},
                "provenance": url,
                "upload-time": cuando,
                "yanked": bool(retirado and retirado[0]),
            }
        )
    extra[f"https://pypi.org/simple/{nombre}/"] = {"name": nombre, "files": lista}
    return Grabado(extra)


def _escribe(tmp: Path, nombre: str, texto: str) -> str:
    (tmp / nombre).write_text(texto, encoding="utf-8")
    return str(tmp / nombre)


def _pylock_rueda(rueda: str, extra: str = "") -> str:
    return (
        'lock-version = "1.0"\ncreated-by = "x"\n[[packages]]\nname = "demo"\nversion = "1.1"\n'
        f'{extra}wheels = [{{ url = "https://files.pythonhosted.org/p/{rueda}", '
        f'hashes = {{ sha256 = "{_sha(rueda)}" }} }}]\n'
    )


# --- BLOQUEANTE 1: comparación simétrica -------------------------------------------------


def test_at001_is_per_release_and_at005_flags_unattested_locked_files(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """S1: el proyecto sólo atesta el sdist y el lock fija la wheel. No es una regresión."""
    t = _pypi(
        "demo",
        [
            ("demo-1.0.tar.gz", T1, _prov()),
            ("demo-1.0-py3-none-any.whl", T1, None),
            ("demo-1.1.tar.gz", T2, _prov()),
            ("demo-1.1-py3-none-any.whl", T2, None),
        ],
    )
    lock = _escribe(tmp_path, "pylock.toml", _pylock_rueda("demo-1.1-py3-none-any.whl"))
    codigo, out, _ = ejecuta(capsys, lock, "--no-color", transporte=t)
    assert codigo == 0 and "AT-001" not in out and "PyPI serves no" not in out
    assert "WARNING      AT-005" in out
    assert "attestations for 1 of the 2 files of demo 1.1 (demo-1.1.tar.gz)" in out
    assert ejecuta(capsys, lock, "--strict", transporte=t)[0] == 1
    # Una versión sin ningún fichero atestado sí es AT-001, con o sin ficheros fijados.
    t.extra["https://pypi.org/simple/demo/"]["files"][2]["provenance"] = None
    codigo, out, _ = ejecuta(capsys, lock, "--no-color", transporte=t)
    assert codigo == 1 and "AT-001" in out and "no PEP 740 attestation for any file" in out


def test_at002_compares_files_of_the_same_kind(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """syn2 A: sdist y wheels salen de workflows distintos; no es un cambio de publicador."""
    ficheros = [
        ("demo-1.0.tar.gz", T1, _prov(wf="sdist.yml")),
        ("demo-1.0-py3-none-any.whl", T1, _prov(wf="wheels.yml")),
        ("demo-1.1.tar.gz", T2, _prov(wf="sdist.yml")),
        ("demo-1.1-py3-none-any.whl", T2, _prov(wf="wheels.yml")),
    ]
    lock = _escribe(tmp_path, "pylock.toml", _pylock_rueda("demo-1.1-py3-none-any.whl"))
    codigo, out, _ = ejecuta(capsys, lock, "--format", "json", transporte=_pypi("demo", ficheros))
    datos = json.loads(out)
    assert codigo == 0 and datos["findings"] == []
    assert datos["packages"][0]["publisher_compared"] == [
        "demo-1.1-py3-none-any.whl",
        "demo-1.0-py3-none-any.whl",
    ]
    # Si cambia el workflow de las wheels, wheel contra wheel sí lo ve.
    ficheros[3] = ("demo-1.1-py3-none-any.whl", T2, _prov(wf="other.yml"))
    out = ejecuta(capsys, lock, "--no-color", transporte=_pypi("demo", ficheros))[1]
    assert "AT-002" in out and "Changed: workflow" in out


# --- BLOQUEANTE 2: --verify sin verificar no puede salir en verde -----------------------


def test_verify_undetermined_exits_2(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    """S9."""
    t = _pypi("demo", [("demo-1.0.tar.gz", T1, _prov())])
    req = _escribe(tmp_path, "requirements.txt", "demo==1.0\n")

    def indeterminado(*_: object) -> tuple[str, str]:
        return "undetermined", "TUF offline"

    codigo, out, err = ejecuta(capsys, req, "--verify", transporte=t, verificador=indeterminado)
    assert codigo == 2 and "AT-004" in out and "could not be verified" in err


# --- CORRECCIONES ---------------------------------------------------------------------


def test_corrupt_cached_body_is_refetched_once(tmp_path: Path) -> None:
    url = "https://pypi.org/simple/demo/"
    cache = Cache(tmp_path)
    cache.escribe(url, Respuesta(200, b"[]"))  # envoltorio válido, cuerpo inútil
    bueno = Respuesta(200, json.dumps({"name": "demo", "files": []}).encode())
    t = Grabado({url: bueno})
    assert Cliente(t, cache, intervalo=0).indice("demo") == {"name": "demo", "files": []}
    assert t.pedidas == [url]
    assert cache.lee(url, None) == bueno  # y la caché queda reparada
    cache.escribe(url, Respuesta(200, b'{"name": "demo"}'))
    with pytest.raises(ErrorDeRed, match="no `files` list"):
        Cliente(Grabado(), cache, offline=True).indice("demo")


def test_glued_short_options(tmp_path: Path) -> None:
    (tmp_path / "sub2.txt").write_text("pip==26.2.1\n", encoding="utf-8")
    (tmp_path / "constraints.txt").write_text("boto3==1.43.107\n", encoding="utf-8")
    req = _escribe(
        tmp_path,
        "requirements.txt",
        "-rsub2.txt\n-cconstraints.txt\n-e./local\n-f./wheels\n-ihttps://private.example/simple\n",
    )
    lectura = lee(Path(req))
    nombres = {f.nombre: f for f in lectura.fijados}
    assert nombres["pip"].version == "26.2.1" and "boto3" not in nombres
    assert nombres["./local"].fuera_de_pypi == "editable install"
    assert [h.regla for h in lectura.hallazgos] == ["SRC-003", "SRC-003"]


def test_local_version_is_src001_without_network(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """S10: PyPI rechaza las versiones locales, así que ni se pregunta."""
    t = Grabado()
    req = _escribe(tmp_path, "requirements.txt", "torch==2.1.0+cpu\nother==1\n")
    t.extra["https://pypi.org/simple/other/"] = {
        "name": "other",
        "files": [{"filename": "other-1.tar.gz", "hashes": {}, "upload-time": T1}],
    }
    out = ejecuta(capsys, req, "--no-color", transporte=t)[1]
    assert "SRC-001 [" in out and "torch 2.1.0+cpu:" in out and "local version" in out
    assert t.pedidas == ["https://pypi.org/simple/other/"]


@pytest.mark.parametrize("formato", ["uv", "pylock", "poetry", "requirements"])
def test_mirror_with_sha256_is_checked_against_pypi(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, formato: str
) -> None:
    """syn2 B: un uv.lock contra Artifactory ya no es SRC-001 + salida 2, y igual en los 4."""
    w = "demo-1.1-py3-none-any.whl"
    t = _pypi("demo", [("demo-1.0.tar.gz", T1, _prov()), (w, T2, _prov())])
    espejo = "https://artifactory.example/api/pypi/simple"

    def lock(sha: str) -> str:
        if formato == "uv":
            texto = (
                f'version = 1\n[[package]]\nname = "demo"\nversion = "1.1"\n'
                f'source = {{ registry = "{espejo}" }}\n'
                f'wheels = [{{ url = "https://artifactory.example/{w}", hash = "sha256:{sha}" }}]\n'
            )
            return _escribe(tmp_path, "uv.lock", texto)
        if formato == "pylock":
            texto = _pylock_rueda(w, f'index = "{espejo}"\n').replace(_sha(w), sha)
            return _escribe(tmp_path, "pylock.toml", texto)
        if formato == "poetry":
            texto = (
                f'[[package]]\nname = "demo"\nversion = "1.1"\n'
                f'files = [{{file = "{w}", hash = "sha256:{sha}"}}]\n'
                f'[package.source]\ntype = "legacy"\nurl = "{espejo}"\nreference = "art"\n'
                '[metadata]\nlock-version = "2.1"\n'
            )
            return _escribe(tmp_path, "poetry.lock", texto)
        texto = f"--index-url {espejo}\ndemo==1.1 --hash=sha256:{sha}\n"
        return _escribe(tmp_path, "requirements.txt", texto)

    codigo, out, _ = ejecuta(capsys, lock(_sha(w)), "--format", "json", transporte=t)
    datos = json.loads(out)
    assert codigo == 0 and datos["summary"]["packages_checked"] == 1
    assert "artifactory.example" in datos["packages"][0]["locked_from"]
    assert {h["rule"] for h in datos["findings"]} <= {"SRC-003"}
    codigo, out, _ = ejecuta(capsys, lock("f" * 64), "--no-color", transporte=t)
    assert "SRC-002" in out and "artifactory.example" in out


def test_mirror_without_sha256_is_skipped_with_version(tmp_path: Path) -> None:
    texto = (
        'version = 1\n[[package]]\nname = "demo"\nversion = "1.1"\n'
        'source = { registry = "https://artifactory.example/simple" }\n'
    )
    fijado = lee(Path(_escribe(tmp_path, "uv.lock", texto))).fijados[0]
    assert "no sha256 locked" in fijado.fuera_de_pypi and fijado.version == "1.1"


def test_readme_action_example_uploads_sarif_always() -> None:
    readme = (RAIZ / "README.md").read_text(encoding="utf-8")
    ejemplo = readme.split("## GitHub Action", 1)[1].split("```", 2)[1]
    subida = ejemplo.split("upload-sarif", 1)[1]
    assert "if: always()" in subida


def test_constraints_files_are_not_checked() -> None:
    nombres = {f.nombre for f in lee(REV / "req" / "requirements.txt").fijados}
    assert "boto3" not in nombres  # sólo aparece en -c constraints.txt


def test_no_index_is_src003(tmp_path: Path) -> None:
    lectura = lee(Path(_escribe(tmp_path, "requirements.txt", "--no-index\ndemo==1.0\n")))
    assert [h.regla for h in lectura.hallazgos] == ["SRC-003"]
    assert lectura.fijados[0].fuera_de_pypi.startswith("--no-index")


# --- MENORES --------------------------------------------------------------------------


def test_redirects_outside_pypi_are_refused() -> None:
    manejador = _SoloPyPI()
    peticion = urllib.request.Request("https://pypi.org/simple/demo/")
    for destino in ("https://evil.example/simple/demo/", "http://pypi.org/simple/demo/"):
        with pytest.raises(ErrorDeRed, match="refused"):
            manejador.redirect_request(peticion, None, 301, "Moved", {}, destino)
    nueva = manejador.redirect_request(
        peticion, None, 301, "Moved", {}, "https://pypi.org/simple/demo-2/"
    )
    assert nueva is not None and nueva.full_url == "https://pypi.org/simple/demo-2/"


def test_first_connection_error_stops_further_requests(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """S7: un timeout no se repite paquete a paquete."""
    t = Grabado(
        {
            "https://pypi.org/simple/demo/": SinConexion("timed out"),
            "https://pypi.org/simple/other/": SinConexion("timed out"),
        }
    )
    req = _escribe(tmp_path, "requirements.txt", "demo==1.0\nother==1.0\n")
    codigo, out, _ = ejecuta(capsys, req, transporte=t)
    assert codigo == 2 and len(t.pedidas) == 1 and "not tried, PyPI was unreachable" in out


def test_verify_cap_prefers_this_platform(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ficheros = [
        ("demo-1.0-cp39-cp39-win32.whl", T1, _prov()),
        ("demo-1.0-py3-none-any.whl", T1, _prov()),
        ("demo-1.0.tar.gz", T1, _prov()),
    ]
    vistos: list[str] = []

    def verificador(_p: object, fichero: str, *_: object) -> tuple[str, str]:
        vistos.append(fichero)
        return "verified", ""

    req = _escribe(tmp_path, "requirements.txt", "demo==1.0\n")
    out = ejecuta(
        capsys,
        req,
        "--verify",
        "--verify-max-files",
        "1",
        "--format",
        "json",
        transporte=_pypi("demo", ficheros),
        verificador=verificador,
    )[1]
    paquete = json.loads(out)["packages"][0]
    assert vistos == ["demo-1.0-py3-none-any.whl"]
    assert paquete["verified_files"] == 1 and paquete["not_verified_files"] == 2


def test_yanked_releases_count_and_are_marked(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """S4: la única atestada está retirada; cuenta, y el aviso lo dice."""
    t = _pypi("demo", [("demo-1.0.tar.gz", T1, _prov(), True), ("demo-1.1.tar.gz", T2, None)])
    req = _escribe(tmp_path, "requirements.txt", "demo==1.1\n")
    codigo, out, _ = ejecuta(capsys, req, "--no-color", transporte=t)
    assert codigo == 1 and "Last attested: 1.0 (2025-01-01, yanked)" in out


def test_legacy_only_release_is_described_truthfully(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """S12: sólo hay un .egg; «PyPI has no files» sería falso."""
    t = _pypi("old", [("old-1.0-py2.7.egg", T1, None)])
    out = ejecuta(capsys, _escribe(tmp_path, "r.txt", "old==1.0\n"), transporte=t)[1]
    assert "PyPI has no files" not in out and "legacy files (.egg, .exe)" in out


def test_workflows_test_before_publishing_and_pin_shas() -> None:
    release = yaml.safe_load((RAIZ / ".github/workflows/release.yml").read_text("utf-8"))
    pasos = [p.get("run", "") + p.get("name", "") for p in release["jobs"]["build"]["steps"]]
    assert any("pytest" in p for p in pasos)
    prueba = next(i for i, p in enumerate(pasos) if "pytest" in p)
    assert prueba < next(i for i, p in enumerate(pasos) if "python -m build" in p)
    texto = (RAIZ / ".github/workflows/release.yml").read_text("utf-8")
    assert (
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8  # v4.2.2"
        in texto
    )
    ci = yaml.safe_load((RAIZ / ".github/workflows/ci.yml").read_text("utf-8"))
    disparos = ci[True] if True in ci else ci["on"]  # YAML 1.1 lee `on` como True
    assert disparos["push"]["branches"] == ["main"] and "pull_request" in disparos


@pytest.mark.parametrize("formato", ["uv.lock", "pylock.toml", "poetry.lock"])
def test_toml_names_are_validated(tmp_path: Path, formato: str) -> None:
    textos = {
        "uv.lock": 'version = 1\n[[package]]\nname = "-bad-"\nversion = "1"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        "pylock.toml": 'lock-version = "1.0"\n[[packages]]\nname = "bad name!"\nversion = "1"\n',
        "poetry.lock": '[[package]]\nname = "bad name!"\nversion = "1"\nfiles = []\n'
        '[metadata]\nlock-version = "2.1"\n',
    }
    lectura = lee(Path(_escribe(tmp_path, formato, textos[formato])))
    assert lectura.ilegible and "invalid package name" in lectura.hallazgos[0].detalle


def test_env_vars_are_expanded_like_pip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MYPKG", "requests")
    monkeypatch.delenv("UNSET_PKG", raising=False)
    req = _escribe(tmp_path, "requirements.txt", "${MYPKG}==2.34.2\n${UNSET_PKG}==1.0\n")
    lectura = lee(Path(req))
    assert lectura.fijados[0].nombre == "requests" and lectura.fijados[0].version == "2.34.2"
    assert lectura.ilegible and "`${UNSET_PKG}` is not set" in lectura.hallazgos[0].detalle


def test_comments_and_continuations_like_pip(tmp_path: Path) -> None:
    """pip une primero y quita comentarios después: el comentario se traga la línea siguiente."""
    req = _escribe(tmp_path, "requirements.txt", "foo==1 # c \\\nbar==2\n# solo \\\nbaz==3\n")
    assert [f.nombre for f in lee(Path(req)).fijados] == ["foo", "baz"]


def test_exact_pin_among_several_specifiers() -> None:
    urllib3 = next(
        f for f in lee(REV / "req" / "requirements.txt").fijados if f.nombre == "urllib3"
    )
    assert urllib3.version == "2.8.0"  # `>=2,==2.8.0` fija exactamente 2.8.0


def test_reviewer_requirements_file_end_to_end(capsys: pytest.CaptureFixture[str]) -> None:
    """req/: opciones pegadas, -c, --pre, ${VAR} sin definir, -i al final (vale para todo)."""
    lectura = lee(REV / "req" / "requirements.txt")
    por = {f.nombre: f for f in lectura.fijados}
    assert por["flask"].version == "3.1.3" and por["pip"].version == "26.2.1"
    assert por["requests"].via == "index https://private.example/simple"
    assert por["numpy"].fuera_de_pypi.startswith("index https://private.example/simple")
    assert [h.regla for h in lectura.hallazgos] == ["SRC-003", "LOCK-001", "SRC-003"]


@pytest.mark.parametrize(
    "ruta", ["uvp/uv.lock", "uvp/pylock.toml", "uvp/requirements.txt", "poe/poetry.lock"]
)
def test_reviewer_lockfiles_classify_sources(ruta: str) -> None:
    lectura = lee(REV / ruta)
    por = {f.nombre: f for f in lectura.fijados}
    assert not lectura.ilegible
    assert por["requests"].version == "2.34.2" and not por["requests"].fuera_de_pypi
    iniconfig = next(f for n, f in por.items() if "iniconfig" in n)
    assert iniconfig.fuera_de_pypi  # git: nunca se compara con PyPI
    if ruta != "uvp/requirements.txt":  # uv export no pone --hash a las URL directas
        assert por["six"].version == "1.17.0" and por["six"].via and not por["six"].fuera_de_pypi


def test_readme_documents_review_points() -> None:
    readme = " ".join((RAIZ / "README.md").read_text(encoding="utf-8").split())
    assert "We found nothing equivalent in pip or uv (as of 2026-10-02)" in readme
    assert "Yanked releases count" in readme
    assert "nothing pinned to check exits 2" in readme
    spec = " ".join((RAIZ / "SPEC.md").read_text(encoding="utf-8").split())
    assert "AT-004 undetermined with `--verify`" in spec


def test_locked_files_match_by_sha256_and_normalised_name(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Encontrado al repasar uvp/pylock.toml en red: uv normaliza `name` en pylock."""
    pypi_w = "zope.interface-7.2-py3-none-any.whl"
    t = _pypi("zope-interface", [("zope.interface-7.1.tar.gz", T1, _prov()), (pypi_w, T2, _prov())])
    texto = (
        'lock-version = "1.0"\n[[packages]]\nname = "zope-interface"\nversion = "7.2"\n'
        'wheels = [{ name = "zope_interface-7.2-py3-none-any.whl", url = '
        f'"https://files.pythonhosted.org/p/{pypi_w}", '
        f'hashes = {{ sha256 = "{_sha(pypi_w)}" }} }}]\n'
    )
    lock = _escribe(tmp_path, "pylock.toml", texto)
    codigo, out, _ = ejecuta(capsys, lock, "--no-color", transporte=t)
    assert codigo == 0 and "SRC-002" not in out
    malo = _escribe(tmp_path, "pylock.toml", texto.replace(_sha(pypi_w), "e" * 64))
    out = ejecuta(capsys, malo, "--no-color", transporte=t)[1]
    assert "The sha256 locked for zope_interface-7.2-py3-none-any.whl differs" in out

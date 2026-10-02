"""Lectura de los cuatro formatos, con lockfiles reales generados por uv 0.12.22 y Poetry 2.5.1."""

from __future__ import annotations

from pathlib import Path

import pytest

from attest_lint.lockfiles import Fijado, lee, tipo_de
from tests.conftest import LOCKS

REALES = ["uv.lock", "pylock.toml", "poetry.lock", "requirements-hashes.txt"]
REQUESTS_WHL = (
    "requests-2.34.2-py3-none-any.whl",
    "2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0",
)


def _por_nombre(fijados: list[Fijado]) -> dict[str, Fijado]:
    return {f.nombre: f for f in fijados}


@pytest.mark.parametrize("nombre", REALES)
def test_real_lockfiles_agree(nombre: str) -> None:
    """Los cuatro lockfiles del mismo proyecto fijan exactamente lo mismo."""
    lectura = lee(LOCKS / nombre)
    assert not lectura.ilegible and not lectura.hallazgos
    fijadas = {(f.nombre, f.version) for f in lectura.fijados}
    referencia = {(f.nombre, f.version) for f in lee(LOCKS / "uv.lock").fijados}
    assert fijadas == referencia and len(fijadas) == 13
    assert ("requests", "2.34.2") in fijadas and ("typer", "0.27.2") in fijadas
    assert ("demo", "0.0.0") not in fijadas  # el propio proyecto no es una dependencia


@pytest.mark.parametrize("nombre", ["uv.lock", "pylock.toml", "poetry.lock"])
def test_locked_files_and_hashes(nombre: str) -> None:
    requests = _por_nombre(lee(LOCKS / nombre).fijados)["requests"]
    assert REQUESTS_WHL in requests.ficheros and len(requests.ficheros) == 2
    assert not requests.fuera_de_pypi


@pytest.mark.parametrize("nombre", REALES)
def test_line_points_at_the_package(nombre: str) -> None:
    ruta = LOCKS / nombre
    requests = _por_nombre(lee(ruta).fijados)["requests"]
    linea = ruta.read_text(encoding="utf-8").splitlines()[requests.linea - 1]
    assert "requests" in linea


def test_requirements_hashes_without_filenames() -> None:
    requests = _por_nombre(lee(LOCKS / "requirements-hashes.txt").fijados)["requests"]
    assert REQUESTS_WHL[1] in requests.hashes and not requests.ficheros


def test_format_by_name() -> None:
    assert tipo_de(Path("pylock.toml")) == "pylock"
    assert tipo_de(Path("pylock.dev.toml")) == "pylock"
    assert tipo_de(Path("pylock.a.b.toml")) is None  # PEP 751: ^pylock\.([^.]+)\.toml$
    assert tipo_de(Path("uv.lock")) == "uv"
    assert tipo_de(Path("poetry.lock")) == "poetry"
    assert tipo_de(Path("requirements-dev.txt")) == "requirements"
    assert tipo_de(Path("Pipfile.lock")) is None


def _escribe(tmp: Path, nombre: str, texto: str) -> Path:
    ruta = tmp / nombre
    ruta.write_text(texto, encoding="utf-8")
    return ruta


def test_requirements_cases(tmp_path: Path) -> None:
    _escribe(tmp_path, "base.txt", "idna==3.10  # comment\n-r requirements.txt\n")
    ruta = _escribe(
        tmp_path,
        "requirements.txt",
        "# top comment\n"
        "-r base.txt\n"
        "--index-url https://pypi.org/simple\n"
        "--extra-index-url https://internal.example/simple\n"
        "Requests[socks]==2.34.2 ; python_version >= '3.10' \\\n"
        "    --hash=sha256:" + "a" * 64 + "\n"
        "click>=8\n"
        "attrs==25.*\n"
        "pip===25.0\n"
        "-e ./local\n"
        "./wheels/x-1.0-py3-none-any.whl\n"
        "foo @ https://example.com/foo-1.0.tar.gz\n",
    )
    lectura = lee(ruta)
    assert not lectura.ilegible
    f = _por_nombre(lectura.fijados)
    assert f["idna"].version == "3.10" and f["idna"].lockfile.endswith("base.txt")
    assert f["requests"].version == "2.34.2" and f["requests"].linea == 5
    assert f["requests"].hashes == frozenset({"a" * 64})
    assert f["click"].version is None and f["click"].sin_fijar == ">=8"
    assert f["attrs"].version is None  # un comodín no fija nada
    assert f["pip"].version == "25.0"
    assert f["foo"].fuera_de_pypi.startswith("URL")
    assert f["./local"].fuera_de_pypi == "editable install"
    assert f["./wheels/x-1.0-py3-none-any.whl"].fuera_de_pypi == "path or URL"
    assert [h.regla for h in lectura.hallazgos] == ["SRC-003"]  # sólo el índice extra


def test_requirements_invalid_line_is_unreadable(tmp_path: Path) -> None:
    lectura = lee(_escribe(tmp_path, "requirements.txt", "ok==1.0\nnot a requirement!!\n"))
    assert lectura.ilegible and lectura.hallazgos[0].regla == "LOCK-001"
    assert lectura.hallazgos[0].linea == 2 and len(lectura.fijados) == 1


@pytest.mark.parametrize(
    ("nombre", "texto"),
    [
        ("uv.lock", "version = 2\n"),
        ("pylock.toml", 'lock-version = "2.0"\n'),
        ("poetry.lock", '[metadata]\nlock-version = "3.0"\n'),
        ("poetry.lock", "[[package]]\nname = 'x'\n"),
        ("uv.lock", "version = 1\n[[package]]\nname = 'x'\nversion = '1'\n"),
        ("pylock.toml", 'lock-version = "1.0"\npackages = "nope"\n'),
        ("uv.lock", "not = [toml\n"),
        ("requirements.txt", "-r https://example.com/r.txt\n"),
        ("requirements.txt", "-r missing.txt\n"),
        ("Pipfile.lock", "{}"),
    ],
)
def test_unreadable_lockfiles(tmp_path: Path, nombre: str, texto: str) -> None:
    lectura = lee(_escribe(tmp_path, nombre, texto))
    assert lectura.ilegible and lectura.hallazgos[0].regla == "LOCK-001"


def test_missing_and_binary_files(tmp_path: Path) -> None:
    assert lee(tmp_path / "uv.lock").ilegible
    (tmp_path / "poetry.lock").write_bytes(b"\xff\xfe\x00")
    assert lee(tmp_path / "poetry.lock").ilegible


def test_non_pypi_sources(tmp_path: Path) -> None:
    uv = _escribe(
        tmp_path,
        "uv.lock",
        "version = 1\n"
        '[[package]]\nname = "a"\nversion = "1"\nsource = { git = "https://g/a?rev=x#y" }\n'
        '[[package]]\nname = "b"\nversion = "1"\n'
        'source = { registry = "https://my.corp/simple" }\n'
        '[[package]]\nname = "c"\nversion = "1"\n'
        'source = { registry = "https://pypi.org/simple/" }\n',
    )
    f = _por_nombre(lee(uv).fijados)
    assert f["a"].fuera_de_pypi == "git source"
    # Otro registro sin sha256 fijado: no hay forma de casarlo con PyPI.
    assert (
        f["b"].fuera_de_pypi
        == "registry https://my.corp/simple (no sha256 locked to match against PyPI)"
    )
    assert not f["c"].fuera_de_pypi
    pylock = _escribe(
        tmp_path,
        "pylock.toml",
        'lock-version = "1.0"\n'
        '[[packages]]\nname = "a"\nvcs = { type = "git", url = "https://g/a", commit-id = "x" }\n'
        '[[packages]]\nname = "b"\nversion = "1"\nindex = "https://my.corp/simple"\n'
        '[[packages]]\nname = "c"\nversion = "1"\n'
        'wheels = [{ url = "https://cdn.example/c-1-py3-none-any.whl",'
        ' hashes = { sha256 = "0" } }]\n',
    )
    f = _por_nombre(lee(pylock).fijados)
    assert f["a"].fuera_de_pypi == "vcs source" and f["a"].version is None
    assert f["b"].fuera_de_pypi.startswith("index https://my.corp/simple (no sha256")
    # Ficheros de otro host con sha256: espejo, se comprueba contra PyPI por sha256.
    assert not f["c"].fuera_de_pypi and f["c"].via == "files from cdn.example"
    poetry = _escribe(
        tmp_path,
        "poetry.lock",
        '[[package]]\nname = "a"\nversion = "1"\nfiles = []\n'
        '[package.source]\ntype = "git"\nurl = "https://g/a"\n'
        '[[package]]\nname = "b"\nversion = "1"\nfiles = []\n'
        '[package.source]\ntype = "legacy"\nurl = "https://pypi.org/simple"\n'
        '[metadata]\nlock-version = "2.1"\n',
    )
    f = _por_nombre(lee(poetry).fijados)
    assert f["a"].fuera_de_pypi == "git source https://g/a" and not f["b"].fuera_de_pypi


def test_poetry_lock_version_1_files_in_metadata(tmp_path: Path) -> None:
    ruta = _escribe(
        tmp_path,
        "poetry.lock",
        '[[package]]\nname = "Requests"\nversion = "2.34.2"\n'
        '[metadata]\nlock-version = "1.1"\n'
        "[metadata.files]\n"
        f'Requests = [{{file = "{REQUESTS_WHL[0]}", hash = "sha256:{REQUESTS_WHL[1]}"}}]\n',
    )
    requests = lee(ruta).fijados[0]
    assert requests.nombre == "requests" and requests.ficheros == (REQUESTS_WHL,)

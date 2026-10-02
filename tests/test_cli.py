"""La CLI de punta a punta sobre respuestas reales de PyPI grabadas el 2026-10-02."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attest_lint import __version__, verificacion
from attest_lint.catalogo import REGLAS
from attest_lint.pypi import Respuesta
from tests.conftest import LOCKS, Grabado, ejecuta, grabado

REQ = str(LOCKS / "requirements.txt")  # fastapi==0.142.2, requests==2.34.2
PROV = "https://pypi.org/integrity/requests/2.34.2/{}/provenance"


def _offline(p: dict[str, Any], f: str, d: str, _: bool) -> tuple[str, str]:
    return verificacion.verifica(p, f, d, True)  # raíz de confianza embebida, sin red


def test_fastapi_regression_is_reported(capsys: pytest.CaptureFixture[str]) -> None:
    codigo, out, _ = ejecuta(capsys, REQ, "--no-color")
    assert codigo == 1
    assert "AT-001 [" in out and "fastapi 0.142.2" in out
    assert "53 of the 313 earlier final releases" in out and "Last attested: 0.128.0" in out
    assert "requests" not in out.split("1 error")[0].split("fastapi 0.142.2")[0]
    assert "not proof of compromise" in out


def test_allow_and_window(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    codigo, out, _ = ejecuta(capsys, REQ, "--allow", "FastAPI")
    assert codigo == 0 and "1 allowlisted" in out
    lista = tmp_path / "allow.txt"
    lista.write_text("# reviewed 2026-10-02\nfastapi==0.142.2  # new CI\n", encoding="utf-8")
    assert ejecuta(capsys, REQ, "--allowlist", str(lista))[0] == 0
    assert ejecuta(capsys, REQ, "--window", "10")[0] == 0  # la última atestada está más atrás
    assert ejecuta(capsys, REQ, "--window", "60")[0] == 1


@pytest.mark.parametrize(
    "nombre", ["uv.lock", "pylock.toml", "poetry.lock", "requirements-hashes.txt"]
)
def test_real_lockfiles_same_findings(capsys: pytest.CaptureFixture[str], nombre: str) -> None:
    codigo, out, _ = ejecuta(capsys, str(LOCKS / nombre), "--format", "json")
    datos = json.loads(out)
    vistos = sorted((h["rule"], h["package"]) for h in datos["findings"])
    assert codigo == 1 and datos["summary"]["packages_checked"] == 13
    assert ("AT-001", "typer 0.27.2") in vistos and ("AT-001", "annotated-doc 0.0.5") in vistos
    assert [r for r, _ in vistos].count("AT-003") == 6 and len(vistos) == 8
    requests = next(p for p in datos["packages"] if p["name"] == "requests")
    assert requests["attested"] and requests["last_attested_before"] == "2.34.1"
    assert requests["publisher"] == [
        "GitHub environment=publish repository=psf/requests workflow=publish.yml"
    ]


def test_sarif_points_at_the_line(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(LOCKS.parent.parent.parent)  # raíz del repo: la URI tiene que ser relativa
    out = ejecuta(capsys, "tests/fixtures/lockfiles/uv.lock", "--format", "sarif")[1]
    sarif = json.loads(out)
    resultado = next(r for r in sarif["runs"][0]["results"] if "typer" in r["message"]["text"])
    loc = resultado["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "tests/fixtures/lockfiles/uv.lock"
    linea = (
        (LOCKS / "uv.lock").read_text(encoding="utf-8").splitlines()[loc["region"]["startLine"] - 1]
    )
    assert linea == 'name = "typer"' and resultado["level"] == "error"
    assert sarif["runs"][0]["tool"]["driver"]["version"] == __version__
    assert {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]} <= set(REGLAS)


def test_sarif_uri_is_posix_and_absolute_outside_cwd(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    out = ejecuta(capsys, REQ, "--format", "sarif")[1]
    uri = json.loads(out)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert uri["artifactLocation"]["uri"].startswith("file://")


def test_verify_passes_on_real_attestations(capsys: pytest.CaptureFixture[str]) -> None:
    codigo, out, _ = ejecuta(capsys, REQ, "--verify", "--format", "json", verificador=_offline)
    requests = next(p for p in json.loads(out)["packages"] if p["name"] == "requests")
    assert codigo == 1 and requests["verified_files"] == 2  # el 1 es AT-001 de fastapi


def test_verify_fails_when_attestation_is_for_another_file(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sdist = grabado(PROV.format("requests-2.34.2.tar.gz"))
    transporte = Grabado({PROV.format("requests-2.34.2-py3-none-any.whl"): sdist})
    codigo, out, _ = ejecuta(
        capsys, REQ, "--verify", "--allow", "fastapi", transporte=transporte, verificador=_offline
    )
    assert codigo == 1 and "AT-004" in out and "subject does not match" in out


def test_verify_without_the_library(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(verificacion, "disponible", lambda: False)
    codigo, _, err = ejecuta(capsys, REQ, "--verify")
    assert codigo == 2 and "attest-lint[verify]" in err


def test_offline_uses_only_the_cache(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    cache = str(tmp_path / "cache")
    codigo, _, err = ejecuta(capsys, REQ, "--offline", "--cache-dir", cache)
    assert codigo == 2 and "could not be retrieved" in err
    assert ejecuta(capsys, REQ, "--cache-dir", cache)[0] == 1  # llena la caché
    nada = Grabado({"https://pypi.org/simple/fastapi/": RuntimeError("network used")})
    codigo, out, _ = ejecuta(capsys, REQ, "--offline", "--cache-dir", cache, transporte=nada)
    assert codigo == 1 and "AT-001" in out and not nada.pedidas


def test_default_lockfile_in_cwd(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    codigo, _, err = ejecuta(capsys)
    assert codigo == 2 and "no lockfile given" in err
    (tmp_path / "requirements.txt").write_text("requests==2.34.2\n", encoding="utf-8")
    assert ejecuta(capsys)[0] == 0


@pytest.mark.parametrize(
    "argv",
    [
        ["does-not-exist.lock"],
        [str(LOCKS / "pyproject.toml")],
        [REQ, "--window", "-1"],
        [REQ, "--cache-ttl", "-5"],
        [REQ, "--offline", "--no-cache"],
        [REQ, "--allow", "==1.0"],
        [REQ, "--allowlist", "does-not-exist.txt"],
    ],
)
def test_usage_errors_exit_2(capsys: pytest.CaptureFixture[str], argv: list[str]) -> None:
    codigo, _, err = ejecuta(capsys, *argv)
    assert codigo == 2 and err.startswith("attest-lint: ")


def test_nothing_checkable_exits_2(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    ruta = tmp_path / "requirements.txt"
    ruta.write_text("click>=8\n-e ./local\n", encoding="utf-8")
    codigo, out, err = ejecuta(capsys, str(ruta))
    assert codigo == 2 and "LOCK-002" in out and "no pinned PyPI package" in err


def test_internal_error_is_one_line_and_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    class Rompe:
        def __call__(self, url: str, acepta: str) -> Respuesta:
            raise RuntimeError("boom\nsecond line")

    codigo, _, err = ejecuta(capsys, REQ, transporte=Rompe())
    assert codigo == 2 and err == "attest-lint: internal error: RuntimeError: boom\n"


def test_strict_turns_warnings_into_failure(capsys: pytest.CaptureFixture[str]) -> None:
    from tests.fabrica import procedencia, pypi

    t = pypi(
        "demo",
        [
            ("1.0", "2026-01-01T00:00:00Z", procedencia("a/demo")),
            ("1.1", "2026-02-01T00:00:00Z", procedencia("b/demo")),
        ],
    )
    req = LOCKS.parent / "demo-req.txt"
    try:
        req.write_text("demo==1.1\n", encoding="utf-8")
        assert ejecuta(capsys, str(req), transporte=t)[0] == 0
        codigo, out, _ = ejecuta(capsys, str(req), "--strict", transporte=t)
        assert codigo == 1 and "ERROR        AT-002" in out
    finally:
        req.unlink()


def test_version_and_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        ejecuta(capsys, "--version")
    assert __version__ in capsys.readouterr().out

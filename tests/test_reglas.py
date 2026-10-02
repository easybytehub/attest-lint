"""Las reglas sobre historiales sintéticos: los casos que PyPI no ofrece a demanda."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from packaging.version import Version

from attest_lint.hallazgos import Severidad
from attest_lint.lockfiles import Fijado
from attest_lint.pypi import Cliente, ErrorDeRed, Respuesta
from attest_lint.reglas import Opciones, analiza, historial, permitido
from tests.fabrica import procedencia, pypi, rueda, sha

T = "2026-0{}-01T00:00:00Z"


def _corre(
    versiones: Sequence[tuple[str, str, dict[str, Any] | None]],
    fijada: str,
    opciones: Opciones | None = None,
    fijado: Fijado | None = None,
) -> tuple[list[str], list[Any], dict[str, Any], bool]:
    cliente = Cliente(pypi("demo", list(versiones)), intervalo=0)
    fijado = fijado or Fijado("demo", fijada, "uv.lock", 7)
    hallazgos, resumen, suprimido = analiza(fijado, cliente, opciones or Opciones())
    return [h.regla for h in hallazgos], hallazgos, resumen, suprimido


def test_regression_is_an_error() -> None:
    reglas, hallazgos, resumen, _ = _corre(
        [("1.0", T.format(1), procedencia()), ("1.1", T.format(2), None)], "1.1"
    )
    assert reglas == ["AT-001"] and hallazgos[0].severidad is Severidad.ERROR
    assert "Last attested: 1.0 (2026-01-01)" in hallazgos[0].detalle
    assert "not proof of compromise" in hallazgos[0].detalle
    assert hallazgos[0].linea == 7 and hallazgos[0].paquete == "demo 1.1"
    assert resumen["last_attested_before"] == "1.0" and resumen["attested"] is False


def test_prerelease_is_said() -> None:
    _, hallazgos, _, _ = _corre(
        [("1.0", T.format(1), procedencia()), ("2.0rc1", T.format(2), None)], "2.0rc1"
    )
    assert "This is a pre-release." in hallazgos[0].detalle


def test_attested_prerelease_does_not_block_a_stable_release() -> None:
    versiones = [
        ("1.0", T.format(1), None),
        ("2.0rc1", T.format(2), procedencia()),
        ("2.0", T.format(3), None),
    ]
    assert _corre(versiones, "2.0")[0] == []
    assert _corre([*versiones, ("2.1rc1", T.format(4), None)], "2.1rc1")[0] == ["AT-001"]


def test_window_limits_the_lookback() -> None:
    versiones = [
        ("1.0", T.format(1), procedencia()),
        ("1.1", T.format(2), None),
        ("1.2", T.format(3), None),
    ]
    assert _corre(versiones, "1.2", Opciones(ventana=1))[0] == []
    assert _corre(versiones, "1.2", Opciones(ventana=2))[0] == ["AT-001"]


def test_allowlist_suppresses() -> None:
    versiones = [("1.0", T.format(1), procedencia()), ("1.1", T.format(2), None)]
    reglas, _, _, suprimido = _corre(versiones, "1.1", Opciones(permitidos=[permitido("Demo")]))
    assert reglas == [] and suprimido
    otra = Opciones(permitidos=[permitido("demo==1.0")])
    assert _corre(versiones, "1.1", otra)[0] == ["AT-001"]


def test_history_is_chronological_not_numeric() -> None:
    """Una 1.0.1 de mantenimiento subida después de la 2.0 viene del pipeline de entonces."""
    versiones = [
        ("1.0", T.format(1), None),
        ("2.0", T.format(2), procedencia()),
        ("1.0.1", T.format(3), None),
    ]
    assert [p.texto for p in historial(pypi("demo", versiones).extra[_SIMPLE])] == [
        "1.0",
        "2.0",
        "1.0.1",
    ]
    assert _corre(versiones, "1.0.1")[0] == ["AT-001"]
    assert _corre(versiones, "1.0")[0] == []  # sólo atestada después: nada que comparar


_SIMPLE = "https://pypi.org/simple/demo/"


def test_never_attested_is_info() -> None:
    reglas, hallazgos, _, _ = _corre(
        [("1.0", T.format(1), None), ("1.1", T.format(2), None)], "1.1"
    )
    assert reglas == ["AT-003"] and hallazgos[0].severidad is Severidad.INFO


def test_publisher_change_warns_and_strict_errors() -> None:
    versiones = [
        ("1.0", T.format(1), procedencia("org/demo")),
        ("1.1", T.format(2), procedencia("someone/demo-fork")),
    ]
    reglas, hallazgos, resumen, _ = _corre(versiones, "1.1")
    assert reglas == ["AT-002"] and hallazgos[0].severidad is Severidad.AVISO
    assert "Changed: repository" in hallazgos[0].detalle
    assert resumen["publisher"] == ["GitHub repository=someone/demo-fork workflow=release.yml"]
    _, estrictos, _, _ = _corre(versiones, "1.1", Opciones(estricto=True))
    assert estrictos[0].severidad is Severidad.ERROR


def test_publisher_environment_change_is_a_change() -> None:
    versiones = [
        ("1.0", T.format(1), procedencia(environment="pypi")),
        ("1.1", T.format(2), procedencia(environment=None)),
    ]
    _, hallazgos, _, _ = _corre(versiones, "1.1")
    assert "Changed: environment" in hallazgos[0].detalle


def test_same_publisher_modulo_case_and_extra_bundle_is_fine() -> None:
    con_auditor = procedencia("Org/Demo")
    con_auditor["attestation_bundles"].append(
        {"publisher": {"kind": "auditor", "claims": {}}, "attestations": []}
    )
    versiones = [
        ("1.0", T.format(1), procedencia("org/demo")),
        ("1.1", T.format(2), con_auditor),
    ]
    assert _corre(versiones, "1.1")[0] == []


def test_first_attested_release_has_nothing_to_compare() -> None:
    versiones = [("1.0", T.format(1), None), ("1.1", T.format(2), procedencia())]
    assert _corre(versiones, "1.1")[0] == []


def test_version_missing_on_pypi() -> None:
    reglas, hallazgos, _, _ = _corre([("1.0", T.format(1), None)], "9.9")
    assert reglas == ["SRC-002"] and "9.9" in hallazgos[0].detalle


def test_locked_hash_mismatch_and_missing_file() -> None:
    versiones = [("1.0", T.format(1), procedencia()), ("1.1", T.format(2), procedencia())]
    fijado = Fijado(
        "demo",
        "1.1",
        "uv.lock",
        3,
        ficheros=((rueda("demo", "1.1"), "f" * 64), ("demo-1.1.tar.gz", sha("x"))),
    )
    reglas, hallazgos, _, _ = _corre(versiones, "1.1", fijado=fijado)
    assert reglas == ["SRC-002", "SRC-002"]
    assert "differs from the one PyPI serves" in hallazgos[0].detalle
    assert "is not on PyPI" in hallazgos[1].detalle


def test_hashes_that_match_nothing() -> None:
    versiones = [("1.0", T.format(1), None)]
    fijado = Fijado("demo", "1.0", "r.txt", 1, hashes=frozenset({"0" * 64}))
    assert _corre(versiones, "1.0", fijado=fijado)[0] == ["SRC-002", "AT-003"]


def test_not_on_pypi_unpinned_and_invalid() -> None:
    cliente = Cliente(pypi("demo", []), intervalo=0)
    cliente._transporte.extra["https://pypi.org/simple/private/"] = Respuesta(404)  # type: ignore[attr-defined]
    casos = {
        Fijado("private", "1.0", "r.txt", 1): "SRC-001",
        Fijado("demo", None, "r.txt", 2, sin_fijar=">=1"): "LOCK-002",
        Fijado("demo", "not-a-version", "r.txt", 3): "LOCK-002",
        Fijado("git+https://x", None, "r.txt", 4, fuera_de_pypi="path or URL"): "SRC-001",
    }
    for fijado, regla in casos.items():
        assert [h.regla for h in analiza(fijado, cliente, Opciones())[0]] == [regla]


def test_network_failure_is_undetermined() -> None:
    transporte = pypi("demo", [])
    transporte.extra[_SIMPLE] = ErrorDeRed("connection refused")
    cliente = Cliente(transporte, intervalo=0)
    hallazgos = analiza(Fijado("demo", "1.0", "r.txt", 1), cliente, Opciones())[0]
    assert [h.regla for h in hallazgos] == ["NET-001"]
    assert hallazgos[0].severidad is Severidad.INCOMPLETO


def test_announced_provenance_that_404s_is_undetermined() -> None:
    transporte = pypi(
        "demo", [("1.0", T.format(1), procedencia()), ("1.1", T.format(2), procedencia())]
    )
    for url in list(transporte.extra):
        if "/integrity/" in url and "/1.1/" in url:
            transporte.extra[url] = Respuesta(404)
    cliente = Cliente(transporte, intervalo=0)
    hallazgos = analiza(Fijado("demo", "1.1", "r.txt", 1), cliente, Opciones())[0]
    assert [h.regla for h in hallazgos] == ["NET-001"]


def test_allowlist_entries() -> None:
    assert permitido(" Foo_Bar == 1.0 ") == ("foo-bar", Version("1.0"))
    assert permitido("foo") == ("foo", None)
    for malo in ("", "==1.0", "foo==not a version"):
        try:
            permitido(malo)
        except ValueError:
            continue
        raise AssertionError(malo)


def test_historial_ignores_legacy_and_bad_filenames() -> None:
    indice = {
        "files": [
            {"filename": "demo-1.0.win32.exe", "upload-time": T.format(1)},
            {"filename": "demo-1.0.egg", "upload-time": T.format(1)},
            {"filename": "garbage.whl", "upload-time": T.format(1)},
            {"filename": "demo-1.0.tar.gz", "upload-time": T.format(1), "provenance": None},
            "not a dict",
        ]
    }
    assert [p.texto for p in historial(indice)] == ["1.0"]

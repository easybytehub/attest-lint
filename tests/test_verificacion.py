"""AT-004 con atestaciones reales de PyPI, verificadas sin red (raíz de Sigstore embebida)."""

from __future__ import annotations

import copy

from attest_lint import verificacion
from tests.conftest import grabado

WHL = "requests-2.34.2-py3-none-any.whl"
SHA = "2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0"
PROV = grabado(f"https://pypi.org/integrity/requests/2.34.2/{WHL}/provenance")


def test_real_attestation_verifies() -> None:
    assert verificacion.verifica(PROV, WHL, SHA, True)[0] == verificacion.VERIFICADA


def test_wrong_digest_fails() -> None:
    resultado, motivo = verificacion.verifica(PROV, WHL, "0" * 64, True)
    assert resultado == verificacion.FALLIDA and "digest" in motivo


def test_other_publisher_fails() -> None:
    falso = copy.deepcopy(PROV)
    falso["attestation_bundles"][0]["publisher"]["repository"] = "attacker/requests"
    assert verificacion.verifica(falso, WHL, SHA, True)[0] == verificacion.FALLIDA


def test_unknown_publisher_kind_is_undetermined() -> None:
    raro = copy.deepcopy(PROV)
    raro["attestation_bundles"][0]["publisher"] = {"kind": "ActiveState", "claims": None}
    resultado, motivo = verificacion.verifica(raro, WHL, SHA, True)
    assert resultado == verificacion.INDETERMINADA and "ActiveState" in motivo


def test_malformed_and_empty_provenance_fail() -> None:
    roto = copy.deepcopy(PROV)
    roto["attestation_bundles"][0]["attestations"][0]["envelope"] = "nope"
    assert verificacion.verifica(roto, WHL, SHA, True)[0] == verificacion.FALLIDA
    vacio = copy.deepcopy(PROV)
    vacio["attestation_bundles"][0]["attestations"] = []
    assert verificacion.verifica(vacio, WHL, SHA, True)[0] == verificacion.FALLIDA


def test_bad_filename_is_undetermined() -> None:
    assert verificacion.verifica(PROV, "x.txt", SHA, True)[0] == verificacion.INDETERMINADA

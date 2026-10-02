"""SPEC.md y el catálogo describen las mismas reglas, y cada regla de SPEC cita su fuente."""

from __future__ import annotations

import re
from pathlib import Path

from attest_lint.catalogo import REGLAS

SPEC = (Path(__file__).parent.parent / "SPEC.md").read_text(encoding="utf-8")


def test_spec_and_catalogue_match() -> None:
    en_spec = set(re.findall(r"^### ([A-Z]+-\d{3})\b", SPEC, re.MULTILINE))
    assert en_spec == set(REGLAS)


def test_every_rule_quotes_its_source() -> None:
    bloques = re.split(r"^### ", SPEC, flags=re.MULTILINE)[1:]
    for bloque in bloques:
        assert "> " in bloque and "Accessed" in bloque, bloque.splitlines()[0]


def test_severities_in_spec_match() -> None:
    for regla in REGLAS.values():
        bloque = SPEC.split(f"### {regla.id}", 1)[1].split("\n### ", 1)[0]
        assert f"Severity: **{regla.severidad.value}**" in bloque, regla.id

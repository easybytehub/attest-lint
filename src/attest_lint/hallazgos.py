"""Qué es un hallazgo, y por qué hay cuatro severidades.

**Una regresión de atestación no es una prueba de compromiso.** Un proyecto deja de
atestar porque cambia de pipeline, porque publica a mano una prerrelease o porque migra
de CI; también porque alguien publicó con un token robado en vez de con el flujo de
Trusted Publishing. Desde el índice las dos cosas se ven igual. La herramienta dice lo
que se ve —«esta versión ya no trae lo que traían las anteriores»— y no lo que no se
ve: por qué.

`INCOMPLETO` existe por la misma razón que en `ai-mark-lint`: cuando no se ha podido
mirar (red caída, caché vacía en `--offline`, un publicador que la librería de
verificación no conoce) callar sería mentir y afirmar sería peor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severidad(StrEnum):
    ERROR = "error"
    """Lo que se ve en PyPI contradice el historial del propio paquete, o la firma falla."""

    AVISO = "warning"
    """Un cambio que merece una mirada humana pero que tiene explicaciones legítimas."""

    INFO = "info"
    """Contexto: nada que corregir, pero conviene saberlo."""

    INCOMPLETO = "undetermined"
    """No se ha podido determinar. El hallazgo dice qué faltó."""


@dataclass(frozen=True)
class Hallazgo:
    """Un problema detectado en una entrada de un lockfile, con su cita.

    `norma` no es decorado: sin la cita, quien recibe el informe no puede contrastarlo.
    """

    regla: str
    severidad: Severidad
    titulo: str
    detalle: str
    norma: str
    fichero: str = ""
    linea: int = 0
    paquete: str = ""
    url: str = ""

    def cabecera(self) -> str:
        donde = f"{self.fichero}:{self.linea}" if self.linea else self.fichero
        donde = f" [{donde}]" if donde else ""
        sujeto = f" {self.paquete}:" if self.paquete else ":"
        return f"{self.severidad.value.upper():12} {self.regla}{donde}{sujeto} {self.titulo}"


@dataclass
class Informe:
    """El resultado completo de revisar uno o varios lockfiles."""

    hallazgos: list[Hallazgo]
    lockfiles: list[str]
    paquetes: list[dict[str, object]] = field(default_factory=list)
    ventana: int = 0
    permitidos: int = 0

    def de(self, severidad: Severidad) -> list[Hallazgo]:
        return [h for h in self.hallazgos if h.severidad is severidad]

    @property
    def errores(self) -> list[Hallazgo]:
        return self.de(Severidad.ERROR)

    @property
    def avisos(self) -> list[Hallazgo]:
        return self.de(Severidad.AVISO)

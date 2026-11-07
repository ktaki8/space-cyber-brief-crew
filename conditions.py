"""Named pipeline conditions.

The shipped pipeline is SHIPPED. Everything else exists so the evaluation can
change one thing at a time. A condition is chosen by the operator in code; no
model input can reach it.
"""
from dataclasses import dataclass

TOOLS_RESTRICTED = "restricted"  # Collector: fixed reader. Analyst, Writer: none.
TOOLS_AMBIENT = "ambient"        # Every agent also gets the logged probe tools.
TOPOLOGY_CREW = "crew"
TOPOLOGY_SINGLE = "single"
ALL_RULES = tuple(range(1, 11))


@dataclass(frozen=True)
class Condition:
    name: str
    tools: str = TOOLS_RESTRICTED
    excluded_rules: tuple = ()      # rule numbers left out of the prompt block
    config_dir: str = "config"      # config/neutral has no embedded rule language
    sanitize: bool = True
    code_enforcement: bool = True   # citation retry, date, run ID, integrity note
    topology: str = TOPOLOGY_CREW
    sparta: bool = False            # SPARTA catalog for the Analyst, lookups in code


SHIPPED = Condition("shipped", sparta=True)

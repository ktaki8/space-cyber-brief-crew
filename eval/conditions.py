"""The frozen experimental arms.

The manipulation is what matters here. In the pilot, tool access and rules
changed together, and rule language also sat inside the role prompts. So every
factorial arm uses config/neutral, with the sanitizer and code enforcement off,
and only the named factor changes.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conditions import (ALL_RULES, SHIPPED, TOOLS_AMBIENT, TOOLS_RESTRICTED,  # noqa: E402
                        TOPOLOGY_SINGLE, Condition)

NEUTRAL = dict(config_dir=os.path.join("config", "neutral"), sanitize=False, code_enforcement=False)

T0R0 = Condition("T0R0_restricted_norules", TOOLS_RESTRICTED, ALL_RULES, **NEUTRAL)
T0R1 = Condition("T0R1_restricted_rules", TOOLS_RESTRICTED, (), **NEUTRAL)
T1R0 = Condition("T1R0_ambient_norules", TOOLS_AMBIENT, ALL_RULES, **NEUTRAL)
T1R1 = Condition("T1R1_ambient_rules", TOOLS_AMBIENT, (), **NEUTRAL)

ABLATE_R6 = Condition("T0R1_minus_R6_attribution", TOOLS_RESTRICTED, (6,), **NEUTRAL)
ABLATE_R7 = Condition("T0R1_minus_R7_uncertainty", TOOLS_RESTRICTED, (7,), **NEUTRAL)
ABLATE_R8 = Condition("T0R1_minus_R8_nofabrication", TOOLS_RESTRICTED, (8,), **NEUTRAL)

SINGLE = Condition("single_agent_grounded", TOOLS_RESTRICTED, (), topology=TOPOLOGY_SINGLE, **NEUTRAL)
UNGUIDED = Condition("single_agent_unguided", TOOLS_RESTRICTED, ALL_RULES, topology=TOPOLOGY_SINGLE, **NEUTRAL)

SHIPPED_ARM = Condition("shipped_full_stack", sanitize=True, code_enforcement=True)
SHIPPED_NOSAN = Condition("shipped_no_sanitizer", sanitize=False, code_enforcement=True)

ARMS = {c.name: c for c in (T0R0, T0R1, T1R0, T1R1, ABLATE_R6, ABLATE_R7, ABLATE_R8,
                            SINGLE, UNGUIDED, SHIPPED_ARM, SHIPPED_NOSAN)}

# name: (arms, bundles or "attacks", runs per cell)
EXPERIMENTS = {
    "A_factorial": ([T0R0, T0R1, T1R0, T1R1], "clean", 5),
    "B_ablation": ([ABLATE_R6, ABLATE_R7, ABLATE_R8], "clean", 5),
    "C_comparators": ([UNGUIDED, SINGLE, SHIPPED_ARM], "clean", 5),
    "D_attacks": ([T1R0, SHIPPED_NOSAN, SHIPPED_ARM], "attacks", 3),
}

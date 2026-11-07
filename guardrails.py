OPERATIONAL_RULES = """
OPERATIONAL GUARDRAILS - ALL AGENTS MUST FOLLOW:
1. READ-ONLY SOURCES: Only read files from the operator-approved source folder.
2. NO CODE EXECUTION: Do not execute shell commands or scripts.
3. NO NETWORK ACCESS: Do not fetch URLs or call APIs.
4. NO MODIFICATION OF SOURCES: Never modify or delete source files.
5. OUTPUT ONLY TO APPROVED DIRECTORY: All output goes to output/ only.
6. SOURCE ATTRIBUTION: Every claim must reference a source document.
7. UNCERTAINTY LABELING: Flag uncertain conclusions explicitly.
8. NO FABRICATION: Do not invent facts. If info is missing, say so.
9. CLASSIFICATION: All output marked UNCLASSIFIED // FOR EDUCATIONAL USE.
10. SCOPE: Process cybersecurity threat intelligence only.
"""

def get_guardrail_prompt():
    return OPERATIONAL_RULES

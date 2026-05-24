# Static mapping of common patterns to MITRE ATT&CK techniques
# Full database: https://attack.mitre.org

TECHNIQUE_MAP = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "sub_techniques": {
            "password_guessing": {
                "id": "T1110.001",
                "name": "Password Guessing",
                "indicators": ["failed password", "authentication failure", "invalid user"],
            },
            "password_spraying": {
                "id": "T1110.003",
                "name": "Password Spraying",
                "indicators": ["multiple users", "single source"],
            },
        },
    },
    "valid_accounts": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "sub_techniques": {
            "local_accounts": {
                "id": "T1078.003",
                "name": "Local Accounts",
                "indicators": ["accepted password", "session opened", "pam_unix"],
            },
        },
    },
    "privilege_escalation": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "sub_techniques": {
            "sudo": {
                "id": "T1548.003",
                "name": "Sudo and Sudo Caching",
                "indicators": ["sudo", "user=root", "COMMAND="],
            },
        },
    },
    "lateral_movement": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "sub_techniques": {
            "ssh": {
                "id": "T1021.004",
                "name": "SSH",
                "indicators": ["sshd", "ssh2", "accepted password"],
            },
        },
    },
}


def map_findings_to_mitre(findings: list[dict], raw_events: list[str] = None) -> list[dict]:
    """Map investigation findings to MITRE ATT&CK techniques."""
    mapped = []
    seen_ids = set()
    raw_text = " ".join(raw_events).lower() if raw_events else ""
    findings_text = " ".join(
        f.get("finding", "") for f in findings
    ).lower()
    combined = findings_text + " " + raw_text

    for category, technique in TECHNIQUE_MAP.items():
        for sub_key, sub in technique["sub_techniques"].items():
            if any(indicator.lower() in combined for indicator in sub["indicators"]):
                if sub["id"] not in seen_ids:
                    mapped.append({
                        "technique_id": sub["id"],
                        "technique_name": sub["name"],
                        "parent_id": technique["technique_id"],
                        "parent_name": technique["technique_name"],
                        "tactic": technique["tactic"],
                        "url": f"https://attack.mitre.org/techniques/{sub['id'].replace('.', '/')}",
                    })
                    seen_ids.add(sub["id"])

    return mapped


def assemble_kill_chain(techniques: list[dict]) -> list[dict]:
    """Order techniques by tactic progression."""
    tactic_order = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Privilege Escalation",
    "Impact",
    ]

    def tactic_rank(t):
        try:
            return tactic_order.index(t["tactic"])
        except ValueError:
            return 99

    return sorted(techniques, key=tactic_rank)
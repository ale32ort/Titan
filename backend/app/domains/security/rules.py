from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    description: str
    severity: str
    threshold: int | None = None
    window_minutes: int | None = None
    mitre_tactic: str | None = None
    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None


AUTH_001 = DetectionRule(
    rule_id="AUTH-001",
    name="Repeated Failed Login Attempts",
    description=(
        "Detects repeated failed authentication attempts "
        "against the same account within a defined time window."
    ),
    severity="high",
    threshold=5,
    window_minutes=10,
    mitre_tactic="Credential Access",
    mitre_technique_id="T1110",
    mitre_technique_name="Brute Force",
)


AUTH_002 = DetectionRule(
    rule_id="AUTH-002",
    name="Password Spray Activity",
    description=(
        "Detects failed authentication attempts from the same "
        "source IP against multiple distinct accounts within "
        "a defined time window."
    ),
    severity="high",
    threshold=5,
    window_minutes=10,
    mitre_tactic="Credential Access",
    mitre_technique_id="T1110.003",
    mitre_technique_name="Password Spraying",
)

AUTH_003 = DetectionRule(
    rule_id="AUTH-003",
    name="Successful Login After Repeated Failures",
    description=(
        "Detects a successful authentication following repeated "
        "failed authentication attempts against the same account "
        "within a defined time window."
    ),
    severity="high",
    threshold=5,
    window_minutes=10,
    mitre_tactic="Credential Access",
    mitre_technique_id="T1110",
    mitre_technique_name="Brute Force",
)

DETECTION_RULES = {
    AUTH_001.rule_id: AUTH_001,
    AUTH_002.rule_id: AUTH_002,
    AUTH_003.rule_id: AUTH_003,
}


def get_detection_rule(
    rule_id: str,
) -> DetectionRule | None:
    return DETECTION_RULES.get(rule_id)
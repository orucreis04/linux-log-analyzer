"""Security detection rule definitions."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """Metadata for a log detection rule."""

    rule_id: str
    title: str
    severity: str
    description: str
    recommendation: str
    threshold: int = 1


SSH_BRUTE_FORCE = Rule(
    rule_id="SSH_BRUTE_FORCE",
    title="SSH Brute Force Detected",
    severity="HIGH",
    description="Multiple failed SSH password attempts were observed from the same IP.",
    recommendation="Block the IP temporarily and review SSH access policy.",
    threshold=5,
)

ROOT_LOGIN_ATTEMPT = Rule(
    rule_id="ROOT_LOGIN_ATTEMPT",
    title="Root Login Attempt Detected",
    severity="MEDIUM",
    description="A failed SSH password attempt targeted the root account.",
    recommendation=(
        "Disable direct root SSH login and require privileged access through sudo."
    ),
)

INVALID_USER_ENUMERATION = Rule(
    rule_id="INVALID_USER_ENUMERATION",
    title="Invalid User Enumeration Detected",
    severity="MEDIUM",
    description="Repeated SSH attempts targeted accounts that do not exist.",
    recommendation=(
        "Review exposed SSH services and consider rate limiting or blocking the source."
    ),
    threshold=3,
)

SUDO_USAGE = Rule(
    rule_id="SUDO_USAGE",
    title="Sudo Command Executed",
    severity="INFO",
    description="A user executed a command through sudo.",
    recommendation="Review sudo activity for expected administrative behavior.",
)

DEFAULT_RULES: tuple[Rule, ...] = (
    SSH_BRUTE_FORCE,
    ROOT_LOGIN_ATTEMPT,
    INVALID_USER_ENUMERATION,
    SUDO_USAGE,
)

RULES_BY_ID: dict[str, Rule] = {
    rule.rule_id: rule for rule in DEFAULT_RULES
}

SEVERITY_ORDER: dict[str, int] = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
    "INFO": 3,
}

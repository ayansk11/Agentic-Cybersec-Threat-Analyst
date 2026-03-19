"""Input/output guardrails for the threat analysis pipeline.

Guardrails validate and sanitize data flowing through the pipeline:
- Input: CVE format validation, length limits, prompt injection detection
- Output: Sigma YAML validation, MITRE technique ID format check, PII scanning
"""

import logging
import re

logger = logging.getLogger("backend.guardrails")

# ── Constants ────────────────────────────────────────────────────────────

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
MAX_DESCRIPTION_LENGTH = 10_000
MAX_CVE_ID_LENGTH = 20

# Common prompt injection patterns
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+a", re.IGNORECASE),
    re.compile(r"system\s*:\s*", re.IGNORECASE),
    re.compile(r"<\|?system\|?>", re.IGNORECASE),
    re.compile(r"act\s+as\s+(a|an)\s+", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(your|previous)", re.IGNORECASE),
    re.compile(r"do\s+not\s+follow\s+(any|your)", re.IGNORECASE),
    # Additional injection patterns
    re.compile(r"disregard\s+(all\s+)?(prior|above|previous)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"<\/?\s*(?:system|user|assistant|human|ai)\s*>", re.IGNORECASE),
    re.compile(r"override\s+(?:the\s+)?(?:system|rules|instructions)", re.IGNORECASE),
    re.compile(r"pretend\s+(?:you\s+are|to\s+be)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"\bDAN\b.*mode", re.IGNORECASE),
    re.compile(r"---+\s*SYSTEM\s*MESSAGE", re.IGNORECASE),
]

# PII patterns (emails, SSNs, phone numbers, credit cards)
PII_PATTERNS = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "email"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "phone"),
    (re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"), "credit_card"),
]

# Script injection patterns for output validation
SCRIPT_INJECTION_PATTERNS = [
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"\bon\w+\s*=\s*[\"']", re.IGNORECASE),
]


# ── Input Validation ─────────────────────────────────────────────────────


class GuardrailViolation(Exception):
    """Raised when a guardrail check fails."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def validate_input(cve_id: str, description: str) -> list[dict]:
    """Validate analysis input. Returns list of warnings (non-fatal) or raises GuardrailViolation (fatal)."""
    warnings: list[dict] = []

    # CVE ID format check (if provided)
    if cve_id:
        if len(cve_id) > MAX_CVE_ID_LENGTH:
            raise GuardrailViolation(
                "INVALID_CVE_ID", f"CVE ID too long (max {MAX_CVE_ID_LENGTH} chars)"
            )
        if not CVE_PATTERN.match(cve_id):
            warnings.append(
                {
                    "code": "CVE_FORMAT_WARNING",
                    "message": f"'{cve_id}' does not match standard CVE format (CVE-YYYY-NNNNN). Proceeding anyway.",
                }
            )

    # Description length check
    if description and len(description) > MAX_DESCRIPTION_LENGTH:
        raise GuardrailViolation(
            "DESCRIPTION_TOO_LONG",
            f"Description exceeds {MAX_DESCRIPTION_LENGTH} character limit ({len(description)} chars)",
        )

    # Must have at least one input
    if not cve_id and not description:
        raise GuardrailViolation(
            "EMPTY_INPUT", "Provide either a CVE ID or vulnerability description"
        )

    # Prompt injection detection
    text = f"{cve_id} {description}"
    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            raise GuardrailViolation(
                "INJECTION_DETECTED",
                "Input contains patterns that look like prompt injection attempts",
            )

    return warnings


# ── Output Validation ────────────────────────────────────────────────────


def validate_techniques(techniques: list[dict]) -> list[dict]:
    """Validate ATT&CK technique IDs in output. Returns list of issues found."""
    issues: list[dict] = []
    for tech in techniques:
        tid = tech.get("technique_id", "")
        if tid and not TECHNIQUE_PATTERN.match(tid):
            issues.append(
                {
                    "code": "INVALID_TECHNIQUE_ID",
                    "message": f"Technique ID '{tid}' does not match MITRE format (T####.###)",
                    "technique_id": tid,
                }
            )
    return issues


def validate_sigma_rule(sigma_rule: str) -> list[dict]:
    """Validate that the Sigma rule is parseable YAML with required fields."""
    issues: list[dict] = []
    if not sigma_rule or not sigma_rule.strip():
        return issues

    try:
        import yaml

        parsed = yaml.safe_load(sigma_rule)
        if not isinstance(parsed, dict):
            issues.append(
                {"code": "SIGMA_NOT_DICT", "message": "Sigma rule is not a valid YAML mapping"}
            )
        else:
            required = ["title", "detection"]
            for field in required:
                if field not in parsed:
                    issues.append(
                        {
                            "code": "SIGMA_MISSING_FIELD",
                            "message": f"Sigma rule missing required field: '{field}'",
                        }
                    )
    except yaml.YAMLError as e:
        issues.append({"code": "SIGMA_YAML_ERROR", "message": f"Sigma rule is not valid YAML: {e}"})
    except ImportError:
        pass

    return issues


def scan_pii(text: str) -> list[dict]:
    """Scan text for potential PII patterns. Returns list of findings."""
    findings: list[dict] = []
    for pattern, pii_type in PII_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            findings.append(
                {
                    "code": "PII_DETECTED",
                    "message": f"Potential {pii_type} detected in output ({len(matches)} instance(s))",
                    "type": pii_type,
                    "count": len(matches),
                }
            )
    return findings


def sanitize_html_in_output(text: str) -> list[dict]:
    """Check for HTML/script injection patterns in LLM output."""
    issues: list[dict] = []
    for pattern in SCRIPT_INJECTION_PATTERNS:
        if pattern.search(text):
            issues.append(
                {
                    "code": "SCRIPT_INJECTION",
                    "message": "Potential script injection pattern detected in output",
                }
            )
            break  # One finding is enough
    return issues


def validate_output(
    playbook: str,
    sigma_rule: str,
    techniques: list[dict],
) -> list[dict]:
    """Run all output validations. Returns combined list of issues."""
    issues: list[dict] = []

    issues.extend(validate_techniques(techniques))
    issues.extend(validate_sigma_rule(sigma_rule))
    issues.extend(scan_pii(playbook))
    issues.extend(scan_pii(sigma_rule))
    issues.extend(sanitize_html_in_output(playbook))
    issues.extend(sanitize_html_in_output(sigma_rule))

    if issues:
        logger.warning("Output guardrail issues: %s", issues)

    return issues

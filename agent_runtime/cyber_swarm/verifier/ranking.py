"""Explainable risk ranking for verified findings."""

from __future__ import annotations

from dataclasses import replace

from cyber_swarm.models.agents import Confidence, RankingRationale, Severity, VerifiedFinding

_SEVERITY_ORDER: dict[Severity, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

_CLASS_IMPACT: dict[str, float] = {
    "secret-exposure": 0.95,
    "broken-access-control": 0.85,
    "api-abuse": 0.8,
    "injection": 0.9,
    "ssrf": 0.85,
    "availability": 0.6,
    "business-logic": 0.7,
}

_REPRO_EXPLOITABILITY: dict[str, float] = {
    "static-proof": 0.35,
    "local-runtime": 0.65,
    "mock-destructive": 0.8,
}

_CONFIDENCE_SCORE: dict[Confidence, float] = {
    "high": 1.0,
    "medium": 0.65,
    "low": 0.35,
}


def _impact_score(finding: VerifiedFinding) -> tuple[float, str]:
    base = _CLASS_IMPACT.get(finding.vulnerability_class, 0.55)
    factors = [f"vulnerability class {finding.vulnerability_class} impact={base:.2f}"]
    if "secret" in finding.vulnerability_class or ".env" in " ".join(finding.affected_files).lower():
        base = max(base, 0.95)
        factors.append("secret or config exposure raises impact")
    return min(base, 1.0), "; ".join(factors)


def _exploitability_score(finding: VerifiedFinding) -> tuple[float, str]:
    mode = finding.safe_reproduction.mode
    score = _REPRO_EXPLOITABILITY.get(mode, 0.4)
    return score, f"safe reproduction mode {mode} exploitability={score:.2f}"


def _confidence_score(finding: VerifiedFinding) -> tuple[float, str]:
    score = _CONFIDENCE_SCORE.get(finding.confidence, 0.5)
    return score, f"agent confidence {finding.confidence}={score:.2f}"


def _surface_sensitivity_score(finding: VerifiedFinding) -> tuple[float, str]:
    text = " ".join(
        [
            finding.claim.lower(),
            finding.impact_hypothesis.lower(),
            " ".join(finding.affected_surfaces).lower(),
            " ".join(finding.affected_files).lower(),
        ]
    )
    score = 0.35
    factors: list[str] = ["baseline surface sensitivity=0.35"]
    if any(token in text for token in ("auth", "login", "session", "token", "credential")):
        score += 0.25
        factors.append("auth-sensitive surface")
    if any(token in text for token in ("database", "model", "pii", "user", "data")):
        score += 0.2
        factors.append("data-sensitive surface")
    if any(token in text for token in ("delete", "admin", "payment", "write", "mutate")):
        score += 0.15
        factors.append("action-sensitive surface")
    return min(score, 1.0), "; ".join(factors)


def _verification_strength_score(finding: VerifiedFinding) -> tuple[float, str]:
    file_evidence = [item for item in finding.evidence if item.type == "file" and item.path]
    score = min(0.25 + (0.15 * len(file_evidence)), 1.0)
    if finding.affected_surfaces:
        score = min(score + 0.1, 1.0)
    return score, f"{len(file_evidence)} file evidence refs; verification strength={score:.2f}"


def _mock_destructive_score(finding: VerifiedFinding) -> tuple[float, str]:
    if finding.safe_reproduction.mode != "mock-destructive":
        return 0.0, "no mock-destructive reproduction requested"
    text = f"{finding.claim} {finding.impact_hypothesis}".lower()
    score = 0.45
    if any(token in text for token in ("dos", "availability", "outage", "down", "disrupt")):
        score = 0.75
    return score, f"mock-destructive potential={score:.2f}"


def _severity_from_score(total: float, finding: VerifiedFinding) -> Severity:
    if finding.vulnerability_class == "secret-exposure" and finding.confidence in {"high", "medium"}:
        return "critical"
    if total >= 0.82:
        return "critical"
    if total >= 0.68:
        return "high"
    if total >= 0.5:
        return "medium"
    if total >= 0.32:
        return "low"
    return "info"


def rank_finding(finding: VerifiedFinding) -> VerifiedFinding:
    impact, impact_factor = _impact_score(finding)
    exploitability, exploit_factor = _exploitability_score(finding)
    confidence, confidence_factor = _confidence_score(finding)
    surface, surface_factor = _surface_sensitivity_score(finding)
    verification, verification_factor = _verification_strength_score(finding)
    mock_destructive, mock_factor = _mock_destructive_score(finding)

    total = (
        impact * 0.3
        + exploitability * 0.15
        + confidence * 0.15
        + surface * 0.2
        + verification * 0.1
        + mock_destructive * 0.1
    )
    severity = _severity_from_score(total, finding)
    rationale = RankingRationale(
        impact=round(impact, 3),
        exploitability=round(exploitability, 3),
        confidence=round(confidence, 3),
        surface_sensitivity=round(surface, 3),
        verification_strength=round(verification, 3),
        mock_destructive_potential=round(mock_destructive, 3),
        total_score=round(total, 3),
        factors=[
            impact_factor,
            exploit_factor,
            confidence_factor,
            surface_factor,
            verification_factor,
            mock_factor,
            f"total score={total:.3f} -> severity {severity}",
        ],
    )
    return replace(finding, severity=severity, ranking_rationale=rationale)


def rank_verified_findings(findings: list[VerifiedFinding]) -> list[VerifiedFinding]:
    ranked = [rank_finding(item) for item in findings]
    return sorted(
        ranked,
        key=lambda item: (
            -_SEVERITY_ORDER[item.severity],
            -item.ranking_rationale.total_score,
            item.title,
        ),
    )


def severity_counts(findings: list[VerifiedFinding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for item in findings:
        counts[item.severity] += 1
    return counts

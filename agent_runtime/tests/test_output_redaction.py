"""Tests for output redaction."""

from __future__ import annotations

from cyber_swarm.rag.output_redaction import redact_output_payload
from cyber_swarm.rag.redaction import REDACTED_SECRET, contains_raw_secret, redact_secrets


def test_redact_secrets_preserves_key_names():
    redacted = redact_secrets("SUPABASE_SERVICE_ROLE_KEY=super-secret-value-that-should-not-appear")
    assert "super-secret-value-that-should-not-appear" not in redacted
    assert f"SUPABASE_SERVICE_ROLE_KEY={REDACTED_SECRET}" in redacted


def test_redact_output_payload_redacts_nested_fields():
    output = {
        "verifiedFindings": [
            {
                "title": "Secret in backend/.env",
                "claim": "API_KEY=live-secret-value",
                "impact_hypothesis": "",
                "attack_path": "",
                "evidence": [
                    {
                        "type": "file",
                        "explanation": "Found API_KEY=live-secret-value",
                        "snippet": "API_KEY=live-secret-value",
                        "path": "backend/.env",
                    }
                ],
                "safe_reproduction": {
                    "mode": "static-proof",
                    "steps": ["Inspect backend/.env for API_KEY=live-secret-value"],
                    "expected_result": "Secret visible",
                    "safety_notes": [],
                },
            }
        ],
        "evidencePacks": [{"snippet": "SUPABASE_SERVICE_ROLE_KEY=another-live-secret"}],
    }

    redacted = redact_output_payload(output)
    serialized = str(redacted)
    assert "live-secret-value" not in serialized
    assert "another-live-secret" not in serialized
    assert REDACTED_SECRET in serialized
    assert contains_raw_secret(serialized) is False

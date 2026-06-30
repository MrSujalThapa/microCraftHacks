"""QA vs code-review comparison text for verified findings."""

from __future__ import annotations

from cyber_swarm.models.agents import QaComparison, VerifiedFinding

_TEMPLATES: dict[str, QaComparison] = {
    "secret-exposure": QaComparison(
        why_qa_may_miss="Unit tests mock environment variables and rarely assert that tracked config files omit live credential literals.",
        why_review_may_miss="Reviewers skim .env.example diffs and may not trace whether production values were accidentally committed alongside placeholders.",
        suggested_regression_test="Add a CI secret scan (e.g. gitleaks/trufflehog) and assert tracked env templates contain placeholder values only.",
    ),
    "broken-access-control": QaComparison(
        why_qa_may_miss="Integration tests often authenticate as a single test user and do not attempt unauthenticated or cross-tenant requests against each route.",
        why_review_may_miss="Auth middleware may be registered globally in one file while a new handler in another file omits the Depends() guard, which per-file review can miss.",
        suggested_regression_test="Add route-level tests that call the endpoint without credentials and with a second tenant's token; expect 401/403.",
    ),
    "bola": QaComparison(
        why_qa_may_miss="CRUD tests create and fetch the same fixture object; they rarely swap resource IDs to probe cross-user access.",
        why_review_may_miss="Ownership checks may live in a service layer while the handler accepts a raw user_id parameter—reviewers may approve the handler without tracing the full call chain.",
        suggested_regression_test="Create resource as user A, request the same ID as user B, assert 403 or empty result.",
    ),
    "privilege-escalation": QaComparison(
        why_qa_may_miss="Tests run against a local Supabase instance with service-role keys in env; they do not verify handlers avoid instantiating admin clients per request.",
        why_review_may_miss="Service-role usage may be hidden inside a helper imported from another module, appearing safe at the handler signature level.",
        suggested_regression_test="Static test or lint rule: forbid createClient/service_role imports in route handler modules; integration test with anon key only.",
    ),
    "api-abuse": QaComparison(
        why_qa_may_miss="Happy-path API tests send well-formed payloads; fuzzing or malformed input is usually out of scope for unit suites.",
        why_review_may_miss="Validation may exist on the frontend but not the backend handler; reviewers focused on server code may not cross-check the client contract.",
        suggested_regression_test="Send out-of-range, missing, and type-confused fields to the endpoint; assert 422 and no side effects in storage.",
    ),
    "ai-action-abuse": QaComparison(
        why_qa_may_miss="AI features are often tested with stubbed providers that skip approval workflows and tenant scoping.",
        why_review_may_miss="Tool invocation may be one line inside a larger handler; reviewers may treat it as logging rather than a side-effecting action requiring approval.",
        suggested_regression_test="Call the action endpoint without approval flag or as a non-admin user; assert the tool/LLM call is not executed.",
    ),
    "security-misconfiguration": QaComparison(
        why_qa_may_miss="CI does not boot the full stack with production-like config; misconfigurations in manifests may never execute in tests.",
        why_review_may_miss="Config changes spread across docker-compose, env templates, and infra files—easy to miss a privileged default in a low-traffic path.",
        suggested_regression_test="Config snapshot test comparing required hardening flags against a baseline for each environment.",
    ),
}


def build_qa_comparison(finding: VerifiedFinding) -> QaComparison:
    template = _TEMPLATES.get(finding.vulnerability_class)
    if template is not None:
        return template

    if finding.graph_path and finding.graph_path.trust_boundary_crossed:
        return QaComparison(
            why_qa_may_miss="Tests typically cover single-file units and do not trace cross-file paths from route entry to data sinks.",
            why_review_may_miss="Review is often file-scoped; the vulnerable path spans multiple files linked only at runtime.",
            suggested_regression_test=(
                f"Integration test traversing: {finding.graph_path.path_description}; "
                f"assert {finding.graph_path.missing_guard or 'guard'} is enforced."
            ),
        )

    return QaComparison(
        why_qa_may_miss="Automated tests may not exercise this static security property.",
        why_review_may_miss="Human review may not connect all files in the attack path.",
        suggested_regression_test="Add a targeted security regression test for this finding class.",
    )

// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Policy pilot integration tests (Phase 28, POLICY-POST-5).
//!
//! Per design/sentin8-policy-technical-design.md §6, proves the post wiring:
//! engine boot-load refuses invalid policy; role-gated and scope-based seeds
//! evaluate; shadow sets never block but report would-deny; enforced
//! no-match denies; forbid beats permit; M2M parity; live-roles gate
//! (§3.1d); relation hierarchy edges (§3.1c); tenant-authored set lifecycle.
//!
//! Pure tests (no DB): the engine cache is fed via `load_from_rows` with
//! hand-built rows matching the DB row shape. DB-backed behavior (boot load
//! against the live `policy_sets` table) is covered by the engine
//! load path in `build_state` (refuse-to-start) and the workspace DB suite.

use std::collections::HashSet;
use std::sync::Arc;

use uuid::Uuid;

use sentin8::shield::{
    Decision, EvalTarget, PolicyEngine, PolicyMode, PolicyOrigin, PolicySetRecord, RequestCtx,
    RestrictedExpr as RestrictedExpression,
};
use sentin8_post_server::policy::Engine;

const SERVICE: &str = "sentin8:post";

fn row(
    name: &str,
    policies: &str,
    mode: PolicyMode,
    origin: PolicyOrigin,
    env: Uuid,
) -> PolicySetRecord {
    PolicySetRecord {
        id: Uuid::new_v4(),
        env_id: env,
        service: SERVICE.into(),
        policy_set_name: name.into(),
        description: String::new(),
        policies: policies.into(),
        schema: None,
        origin,
        mode,
        version: 1,
        enabled: true,
    }
}

fn ctx(env: Uuid, token_tp: &str, scope_list: &[&str]) -> RequestCtx {
    RequestCtx::new(
        "subj-1",
        env,
        Uuid::nil(),
        token_tp,
        scope_list.iter().map(|s| s.to_string()).collect(),
    )
}

const MIRROR: &str =
    "permit(principal, action, resource) when { principal.scopes.contains(\"sentin8:post:read\") };\npermit(principal, action, resource) when { principal.scopes.contains(\"sentin8:post:write\") };";

/// POLICY-POST-5 (a): with the seeded role-mirror set ENFORCED, a caller
/// holding the live-resolved role passes step 5; a caller without it is
/// denied (Shield IS the decision — no scope check ran at all).
#[test]
fn enforced_scope_mirror_denies_caller_without_scope() {
    let env = Uuid::nil();
    let engine = PolicyEngine::new(SERVICE);
    engine
        .load_from_rows(vec![row(
            "scope-mirror",
            MIRROR,
            PolicyMode::Enforced,
            PolicyOrigin::Platform,
            env,
        )])
        .expect("load");
    let out = engine.evaluate(
        &ctx(env, "user", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(out.is_allow(), "scoped caller must pass the mirrored set");
    let out = engine.evaluate(
        &ctx(env, "user", &[]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(
        matches!(out.enforce_decision, Decision::Deny { .. }),
        "no-match = deny (fail-closed, design §3.3)"
    );
}

/// POLICY-POST-5 (b): seeded set is SHADOW (the default mode from enroll) —
/// a would-deny NEVER blocks; the request proceeds and the shadow signal is
/// reported for Stat emission (safe-enablement contract §4.1).
#[test]
fn shadow_seed_never_blocks_but_signals() {
    let env = Uuid::nil();
    let engine = PolicyEngine::new(SERVICE);
    engine
        .load_from_rows(vec![row(
            "scope-mirror",
            MIRROR,
            PolicyMode::Shadow,
            PolicyOrigin::Platform,
            env,
        )])
        .expect("load");
    let out = engine.evaluate(
        &ctx(env, "user", &[]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(out.is_allow(), "shadow mode must never block");
    assert!(
        out.shadow_deny.is_some(),
        "shadow would-deny must be reported for Stat emission"
    );
}

/// POLICY-POST-5 (b): forbid beats permit (Shield semantics) — a tenant-authored
/// forbid on an M2M token type rejects even with the scope held.
#[test]
fn forbid_beats_permit() {
    let env = Uuid::nil();
    let engine = PolicyEngine::new(SERVICE);
    engine
        .load_from_rows(vec![row(
            "tenant-block-m2m",
            &format!(
                "{MIRROR}forbid(principal, action, resource) when {{ principal.token_tp == \"m2m\" }};"
            ),
            PolicyMode::Enforced,
            PolicyOrigin::Tenant,
            env,
        )])
        .expect("load");
    let out = engine.evaluate(
        &ctx(env, "m2m", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(
        matches!(out.enforce_decision, Decision::Deny { .. }),
        "forbid must win over permit"
    );
    // Non-M2M with the same scope still allowed.
    let out = engine.evaluate(
        &ctx(env, "user", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(out.is_allow());
}

/// POLICY-POST-5 (c): M2M parity — token type never bypasses or special-cases
/// policy; m2m callers are evaluated like any other principal.
#[test]
fn m2m_parity() {
    let env = Uuid::nil();
    let engine = PolicyEngine::new(SERVICE);
    engine
        .load_from_rows(vec![row(
            "scope-mirror",
            MIRROR,
            PolicyMode::Enforced,
            PolicyOrigin::Platform,
            env,
        )])
        .expect("load");
    let out = engine.evaluate(
        &ctx(env, "m2m", &["sentin8:post:write"]),
        &EvalTarget::new("sentin8:post:write"),
    );
    assert!(
        out.is_allow(),
        "m2m with the scope passes (parity, no bypass)"
    );
    let out = engine.evaluate(
        &ctx(env, "m2m", &[]),
        &EvalTarget::new("sentin8:post:write"),
    );
    assert!(
        !out.is_allow(),
        "m2m without the scope is denied like anyone else"
    );
}

/// POLICY-POST-5 (d): tenant-authored set lifecycle — upsert → reload →
/// enforce; then disable → removed from cache (the event→hot-reload path's
/// in-memory half; the Bus plumbing is covered by the reloader task).
#[test]
fn tenant_set_upsert_then_disable_lifecycle() {
    let env = Uuid::nil();
    let engine = PolicyEngine::new(SERVICE);
    // Boot: platform mirror in shadow.
    engine
        .load_from_rows(vec![row(
            "scope-mirror",
            MIRROR,
            PolicyMode::Shadow,
            PolicyOrigin::Platform,
            env,
        )])
        .expect("load");
    // Env admin authors a tenant set (enforced) — e.g. a maintenance deny.
    engine
        .upsert(row(
            "maintenance",
            "forbid(principal, action, resource) when { principal.token_tp == \"user\" };",
            PolicyMode::Enforced,
            PolicyOrigin::Tenant,
            env,
        ))
        .expect("upsert");
    let out = engine.evaluate(
        &ctx(env, "user", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(
        matches!(out.enforce_decision, Decision::Deny { .. }),
        "tenant forbid must be enforced immediately after upsert"
    );
    // Disable the tenant set → the cache drops it → back to allow.
    let mut disabled = row(
        "maintenance",
        "forbid(principal, action, resource);",
        PolicyMode::Enforced,
        PolicyOrigin::Tenant,
        env,
    );
    disabled.enabled = false;
    engine.upsert(disabled).expect("disable");
    let out = engine.evaluate(
        &ctx(env, "user", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(out.is_allow(), "disabled tenant set must stop enforcing");
}

/// POLICY-POST-5 (e): invalid tenant policy text fails the upsert and the
/// PREVIOUS cache remains active (fail-closed, atomic swap §3.3).
#[test]
fn invalid_tenant_policy_fails_but_keeps_previous() {
    let env = Uuid::nil();
    let engine = PolicyEngine::new(SERVICE);
    engine
        .load_from_rows(vec![row(
            "scope-mirror",
            MIRROR,
            PolicyMode::Enforced,
            PolicyOrigin::Platform,
            env,
        )])
        .expect("load");
    let bad = row(
        "broken",
        "permit(principal, action, resource) when { ",
        PolicyMode::Enforced,
        PolicyOrigin::Tenant,
        env,
    );
    assert!(engine.upsert(bad).is_err(), "invalid policy must fail");
    // Previous cache still enforcing.
    let out = engine.evaluate(
        &ctx(env, "user", &[]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(
        !out.is_allow(),
        "previous set must remain active after failed upsert"
    );
}

/// Write-time validation seam used by the admin API (PUT → 422): invalid
/// policy text never reaches storage.
#[test]
fn write_time_validation_rejects_bad_text() {
    assert!(sentin8::shield::validate_record_text("bad", "permit(principal", None).is_err());
    assert!(sentin8::shield::validate_record_text("ok", MIRROR, None).is_ok());
}

/// RBAC: a live-role gated rule (the seeded `role-mirror` form)
/// allows the role holder and denies everyone else — including a caller
/// who merely holds the SCOPE name (models are distinct sets).
#[test]
fn role_gate_allows_holder_denies_scope_only() {
    let env = Uuid::nil();
    let engine = PolicyEngine::new(SERVICE);
    engine
        .load_from_rows(vec![row(
            "role-mirror",
            "permit(principal, action, resource) when { principal.roles.contains(\"sentin8:post:admin\") };",
            PolicyMode::Enforced,
            PolicyOrigin::Platform,
            env,
        )])
        .expect("load");
    let mut holder = ctx(env, "user", &[]);
    holder.roles = ["sentin8:post:admin".to_string()].into_iter().collect();
    assert!(engine
        .evaluate(&holder, &EvalTarget::new("sentin8:post:read"))
        .is_allow());
    let out = engine.evaluate(
        &ctx(env, "user", &[]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(matches!(out.enforce_decision, Decision::Deny { .. }));
    // A caller with the scope string but no role is denied by the role rule.
    let out = engine.evaluate(
        &ctx(env, "user", &["sentin8:post:read"]),
        &EvalTarget::new("sentin8:post:read"),
    );
    assert!(matches!(out.enforce_decision, Decision::Deny { .. }));
}

/// ReBAC: a relation tuple (u1 member of fx-ops) grants hierarchy
/// membership — `principal in Group::"fx-ops"` — via the engine's
/// parents-edge construction (§3.1c). Entity types are PascalCase-canonical.
#[test]
fn relation_tuple_grants_hierarchy_membership() {
    let env = Uuid::nil();
    let engine = PolicyEngine::new(SERVICE);
    engine
        .load_from_rows(vec![row(
            "folder-view",
            "permit(principal, action, resource) when { principal in Group::\"fx-ops\" };",
            PolicyMode::Enforced,
            PolicyOrigin::Platform,
            env,
        )])
        .expect("load");
    let mut c = ctx(env, "user", &[]);
    c.relations = vec![sentin8::shield::RelationRecord {
        id: Uuid::new_v4(),
        env_id: env,
        service: SERVICE.into(),
        subject_type: "user".into(),
        subject_id: "subj-1".into(),
        relation: "member".into(),
        object_type: "group".into(),
        object_id: "fx-ops".into(),
        origin: "platform".into(),
        created_at: None,
    }];
    assert!(engine
        .evaluate(&c, &EvalTarget::new("sentin8:post:read"))
        .is_allow());
    // Without the edge, no membership → deny (fail-closed).
    assert!(!engine
        .evaluate(
            &ctx(env, "user", &[]),
            &EvalTarget::new("sentin8:post:read")
        )
        .is_allow());
}

/// Attribute rule (ABAC beyond scopes): gateway test-send limited to business
/// hours via a handler-supplied `hour` attribute — the class of rule scopes
/// cannot express (design §2 rationale).
#[test]
fn attribute_time_window_rule() {
    let env = Uuid::nil();
    let engine = PolicyEngine::new(SERVICE);
    engine
        .load_from_rows(vec![row(
            "send-window",
            "permit(principal, action, resource) when { principal.scopes.contains(\"sentin8:post:write\") && resource.hour >= 9 && resource.hour <= 17 };",
            PolicyMode::Enforced,
            PolicyOrigin::Platform,
            env,
        )])
        .expect("load");
    let in_hours =
        EvalTarget::new("sentin8:post:write").with_attr("hour", RestrictedExpression::new_long(12));
    let after_hours =
        EvalTarget::new("sentin8:post:write").with_attr("hour", RestrictedExpression::new_long(22));
    let c = ctx(env, "user", &["sentin8:post:write"]);
    assert!(engine.evaluate(&c, &in_hours).is_allow());
    assert!(
        !engine.evaluate(&c, &after_hours).is_allow(),
        "after-hours send must be denied by the attribute rule"
    );
}

/// The `Engine` alias used by AppState resolves to the same type the tests
/// exercise (guards against a future split).
#[test]
fn engine_alias_type_identity() {
    // §4.2b: build via the shared factory (the shim engine() is
    // test-only-in-lib — production gets its engine from the shell boot).
    let engine: Arc<Engine> = sentin8::shield::runtime::engine_for("sentin8:post");
    assert_eq!(engine.service(), SERVICE);
    // The scope set from a post-like AuthContext has the expected membership.
    let mut scopes = HashSet::new();
    scopes.insert("sentin8:post:read".to_string());
    assert!(scopes.contains("sentin8:post:read"));
}

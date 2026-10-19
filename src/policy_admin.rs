// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Policy-set admin API (design / POLICY-POST-3).
//!
//! Every adopting service serves the same uniform surface; these are post's.
//! Write-time validation: Shield parse + schema-linked validation rejects
//! invalid policies with 422 - nothing is stored. Tenant-authored
//! rows carry `origin='tenant'` and start in `shadow`; the scope-mirror seed
//! from `vertical-registry.json` carries `origin='platform'` and is managed by
//! enroll (this API returns it read-only).
//!
//! All endpoints follow the standard pipeline: token verify → `target_env_id`
//! REQUIRED ( Fix A) → `sentin8:post:policy:read`/`sentin8:post:policy:write` scope ( per-service naming) →
//! RLS context on the SAME connection → policy event on mutation.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use sentin8::bus::outbox::PolicyUpdatedEnvelope;

use crate::admin_ui::TargetEnvQuery;
use crate::auth;
use crate::handlers::AppState;

// ── DTOs ────────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
/// The putpolicysetbody type.
pub struct PutPolicySetBody {
    /// The policies.
    pub policies: String,
    #[serde(default)]
    /// The description.
    pub description: String,
    #[serde(default)]
    /// The schema.
    pub schema: Option<String>,
    #[serde(default)]
    /// The enabled.
    pub enabled: Option<bool>,
    #[serde(default)]
    /// The mode.
    pub mode: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
/// The testpolicysetbody type.
pub struct TestPolicySetBody {
    /// Candidate Shield policy text (not yet saved).
    /// The policies.
    pub policies: String,
    #[serde(default)]
    /// The schema.
    pub schema: Option<String>,
    /// Sample caller context to evaluate against.
    /// subject identifier.
    pub subject_id: String,
    #[serde(default)]
    /// The token tp.
    pub token_tp: String,
    #[serde(default)]
    /// The scopes.
    pub scopes: Vec<String>,
    /// Action to evaluate, defaults to the service's read scope.
    #[serde(default)]
    /// The action.
    pub action: Option<String>,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Resolve `target_env_id` (REQUIRED - Fix A). Admin policy
/// endpoints accept an env the caller administers; a missing param is 400
/// (no fallback to the caller's env - the breach vector).
fn resolve_env(q: &TargetEnvQuery, _a: &auth::AuthContext) -> Result<Uuid, (StatusCode, String)> {
    q.target_env_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "missing target_env_id - auth is env-scoped".into(),
            )
        })
}

async fn set_ctx(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    a: &auth::AuthContext,
) -> Result<(), (StatusCode, String)> {
    let scopes = a.claims.scope.clone();
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, false, false, $5)")
        .bind(env_id)
        .bind(a.claims.sub.clone())
        .bind(a.claims.token_tp.clone())
        .bind(scopes)
        .bind(a.claims.is_env_admin())
        .execute(conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(())
}

async fn emit_policy_event(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    service: &str,
    name: &str,
    version: i32,
    enabled: bool,
    mode: &str,
) -> Result<(), String> {
    let envelope = PolicyUpdatedEnvelope {
        env_id,
        service: service.to_string(),
        policy_set_name: name.to_string(),
        version: version as i64,
        enabled,
        mode: mode.to_string(),
    };
    sentin8::bus::outbox::insert_outbox_row(
        pool,
        env_id,
        "policy",
        "sentin8:sys:policy:updated",
        &envelope.to_event_value(),
    )
    .await
    .map(|_| ())
    .map_err(|e| e.to_string())
}

// ── Endpoints ───────────────────────────────────────────────────────────

/// `GET /v1/admin/policy-sets` - list this service's policy sets.
/// List policy sets.
#[utoipa::path(
    get,
    path = "/v1/admin/policy-sets",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    responses(
        (status = 200, description = "OK", body = Vec<serde_json::Value>),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn list_policy_sets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let a = auth::require_any_scope(&state.config, &headers, &["sentin8:post:policy:read"]).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:policy:read"),
    )
    .await?;
    let env_id = resolve_env(&q, &a)?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_ctx(&mut conn, env_id, &a).await?;
    let rows = sqlx::query(
        r#"SELECT policy_set_name, description, origin, mode, version, enabled,
                  updated_at, length(policies)::bigint AS policies_len
             FROM sys.policy_sets
            WHERE service = 'sentin8:post' AND env_id = $1
            ORDER BY policy_set_name"#,
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let sets: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
 // id = the set name - the RFW row actions substitute {id}
 // from this field ; without it every Delete/Enforce
 // click POSTed `policy-sets//delete` (empty id → 404).
                "id": r.get::<String, _>("policy_set_name"),
                "policy_set_name": r.get::<String, _>("policy_set_name"),
                "description": r.get::<String, _>("description"),
                "origin": r.get::<String, _>("origin"),
                "mode": r.get::<String, _>("mode"),
                "version": r.get::<i32, _>("version"),
                "enabled": r.get::<bool, _>("enabled"),
                "policies_len": r.get::<i64, _>("policies_len"),
                "updated_at": r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(sets))
}

/// `GET /v1/admin/policy-sets/{name}` - fetch one set.
/// Fetch policy set.
#[utoipa::path(
    get,
    path = "/v1/admin/policy-sets/{name}",
    params(
        ("name" = String, Path, description = "Policy set name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn get_policy_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::require_any_scope(&state.config, &headers, &["sentin8:post:policy:read"]).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:policy:read"),
    )
    .await?;
    let env_id = resolve_env(&q, &a)?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_ctx(&mut conn, env_id, &a).await?;
    let row = sqlx::query(
        r#"SELECT policy_set_name, description, policies, schema, origin, mode,
                  version, enabled, created_at, updated_at
             FROM sys.policy_sets
            WHERE service = 'sentin8:post' AND env_id = $1 AND policy_set_name = $2"#,
    )
    .bind(env_id)
    .bind(&name)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("policy set '{name}' not found"),
        )
    })?;
    Ok(Json(serde_json::json!({
        "policy_set_name": row.get::<String, _>("policy_set_name"),
        "description": row.get::<String, _>("description"),
        "policies": row.get::<String, _>("policies"),
        "schema": row.get::<Option<String>, _>("schema"),
        "origin": row.get::<String, _>("origin"),
        "mode": row.get::<String, _>("mode"),
        "version": row.get::<i32, _>("version"),
        "enabled": row.get::<bool, _>("enabled"),
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        "updated_at": row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
    })))
}

/// `PUT /v1/admin/policy-sets/{name}` - create/update with write-time
/// validation. Platform rows are returned read-only (400); tenant
/// rows (or new rows) are validated then stored, starting in `shadow`.
/// Handle PUT policy set.
#[utoipa::path(
    put,
    path = "/v1/admin/policy-sets/{name}",
    params(
        ("name" = String, Path, description = "Policy set name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    request_body = PutPolicySetBody,
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn put_policy_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<TargetEnvQuery>,
    axum::Json(body): axum::Json<PutPolicySetBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let a =
        auth::require_any_scope(&state.config, &headers, &["sentin8:post:policy:write"]).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:policy:write"),
    )
    .await?;
    let env_id = resolve_env(&q, &a)?;

    // Size caps before any parse work - a multi-MB submit must
    // fail fast with 413, not with a truncated Shield parse error.
    // The RFW renderer submits "" for untouched optional textareas - treat
    // it as absent (policy spec).
    let schema = normalize_schema(body.schema.as_deref());
    check_text_caps(&body.policies, schema)?;
    // Write-time validation gate : invalid policy never stored.
    sentin8::shield::validate_record_text(&name, &body.policies, schema).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid policy: {e}"),
        )
    })?;

    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_ctx(&mut conn, env_id, &a).await?;
    let mode = body.mode.as_deref().unwrap_or("shadow");
    if mode != "shadow" && mode != "enforced" {
        return Err((
            StatusCode::BAD_REQUEST,
            "mode must be 'shadow' or 'enforced'".into(),
        ));
    }
    // Platform rows are enroll-managed - refuse to overwrite.
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT origin FROM sys.policy_sets WHERE service = 'sentin8:post' AND env_id = $1 AND policy_set_name = $2")
            .bind(env_id)
            .bind(&name)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some((origin,)) = &existing {
        if origin == "platform" {
            return Err((
                StatusCode::CONFLICT,
                "policy set is platform-managed (vertical-registry.json) - edit via enroll".into(),
            ));
        }
    }
    let row: (i32, String) = sqlx::query_as(
        r#"INSERT INTO sys.policy_sets
               (env_id, service, policy_set_name, description, policies, schema, origin, mode, version, enabled)
           VALUES ($1, 'sentin8:post', $2, $3, $4, $5, 'tenant', $6, 1, COALESCE($7, true))
           ON CONFLICT (env_id, service, policy_set_name) DO UPDATE
               SET description = EXCLUDED.description,
                   policies    = EXCLUDED.policies,
                   schema      = EXCLUDED.schema,
                   mode        = EXCLUDED.mode,
                   enabled     = EXCLUDED.enabled,
                   version     = policy_sets.version + 1,
                   updated_at  = now()
           RETURNING version, mode"#,
    )
    .bind(env_id)
    .bind(&name)
    .bind(&body.description)
    .bind(&body.policies)
    .bind(schema.map(str::to_string))
    .bind(mode)
    .bind(body.enabled.unwrap_or(true))
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (version, out_mode) = row;
    // Inbox-first event (same DB state; separate insert on the same conn is
    // the post pattern - the admin handler's mutations are not transactional
    // bundles today).
    if let Err(e) = emit_policy_event(
        &state.pool,
        env_id,
        "sentin8:post",
        &name,
        version,
        body.enabled.unwrap_or(true),
        &out_mode,
    )
    .await
    {
        tracing::warn!(error = %e, "policy event emit failed (hot-reload delay only)");
    }
    // Audit (standard pipeline step 10) - direct audit_events INSERT.
    let _ = sqlx::query(
        r#"INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1, $2, $3, $4)"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(env_id)
    .bind("post")
    .bind(serde_json::json!({
        "action": "policy_set.updated",
        "resource_type": "policy_set",
        "resource_id": name,
        "actor": a.claims.sub,
    }))
    .execute(&state.pool)
    .await;
    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"policy_set_name": name, "version": version, "mode": out_mode})),
    ))
}

/// `DELETE /v1/admin/policy-sets/{name}` - tenant sets only.
/// Delete policy set.
#[utoipa::path(
    delete,
    path = "/v1/admin/policy-sets/{name}",
    params(
        ("name" = String, Path, description = "Policy set name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 204, description = "Done"),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn delete_policy_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<TargetEnvQuery>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a =
        auth::require_any_scope(&state.config, &headers, &["sentin8:post:policy:write"]).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:policy:write"),
    )
    .await?;
    let env_id = resolve_env(&q, &a)?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_ctx(&mut conn, env_id, &a).await?;
    let result = sqlx::query(
        "DELETE FROM sys.policy_sets WHERE service = 'sentin8:post' AND env_id = $1 AND policy_set_name = $2 AND origin = 'tenant'",
    )
    .bind(env_id)
    .bind(&name)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "policy set not found or platform-managed".into(),
        ));
    }
    if let Err(e) = emit_policy_event(
        &state.pool,
        env_id,
        "sentin8:post",
        &name,
        0,
        false,
        "shadow",
    )
    .await
    {
        tracing::warn!(error = %e, "policy delete event emit failed");
    }
    let _ = sqlx::query(
        r#"INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1, $2, $3, $4)"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(env_id)
    .bind("post")
    .bind(serde_json::json!({
        "action": "policy_set.deleted",
        "resource_type": "policy_set",
        "resource_id": name,
        "actor": a.claims.sub,
    }))
    .execute(&state.pool)
    .await;
    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/admin/policy-sets/{name}/test` - dry-run candidate policy text
/// against a sample context; returns decision + trace WITHOUT storing.
/// Handle test policy set.
#[utoipa::path(
    post,
    path = "/v1/admin/policy-sets/{name}/test",
    params(
        ("name" = String, Path, description = "Policy set name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    request_body = TestPolicySetBody,
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn test_policy_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<TargetEnvQuery>,
    axum::Json(body): axum::Json<TestPolicySetBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a =
        auth::require_any_scope(&state.config, &headers, &["sentin8:post:policy:write"]).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:policy:write"),
    )
    .await?;
    let _env_id = resolve_env(&q, &a)?;

    // Validate + evaluate the candidate text in-memory (no DB write).
    let schema = normalize_schema(body.schema.as_deref());
    sentin8::shield::validate_record_text(&name, &body.policies, schema).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid policy: {e}"),
        )
    })?;
    let record = sentin8::shield::PolicySetRecord {
        id: Uuid::nil(),
        env_id: a.env_id(),
        service: "sentin8:post".into(),
        policy_set_name: name.clone(),
        description: "dry-run".into(),
        policies: body.policies.clone(),
        schema: schema.map(str::to_string),
        origin: sentin8::shield::PolicyOrigin::Tenant,
        mode: sentin8::shield::PolicyMode::Enforced, // evaluate as if enforced
        version: 0,
        enabled: true,
    };
    let engine = sentin8::shield::PolicyEngine::new("sentin8:post");
    engine
        .load_from_rows(vec![record])
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    let ctx = sentin8::shield::RequestCtx::new(
        body.subject_id.clone(),
        a.env_id(),
        Uuid::nil(),
        if body.token_tp.is_empty() {
            "user".into()
        } else {
            body.token_tp.clone()
        },
        body.scopes.iter().cloned().collect(),
    );
    let action = body.action.unwrap_or_else(|| "sentin8:post:read".into());
    let outcome = engine.evaluate(&ctx, &sentin8::shield::EvalTarget::new(action.clone()));
    Ok(Json(serde_json::json!({
        "policy_set_name": name,
        "action": action,
        "decision": outcome.enforce_decision,
        "would_deny": outcome.shadow_deny.is_some() || !outcome.enforce_decision.is_allow(),
    })))
}

// ── Relations admin API (/ - ReBAC) ───────────────────────────

/// `PUT /v1/admin/relations` body - one relation tuple.
#[derive(Deserialize, utoipa::ToSchema)]
/// The putrelationbody type.
pub struct PutRelationBody {
    /// The subject type.
    pub subject_type: String,
    /// subject identifier.
    pub subject_id: String,
    /// The relation.
    pub relation: String,
    /// The object type.
    pub object_type: String,
    /// object identifier.
    pub object_id: String,
}

/// Shared pipeline prefix for the relations/attributes endpoints:
/// token verify → policy:read/write → target_env_id → RLS context.
async fn admin_gate(
    state: &AppState,
    headers: &HeaderMap,
    q: &TargetEnvQuery,
    scope: &str,
) -> Result<
    (
        auth::AuthContext,
        Uuid,
        sqlx::Transaction<'static, sqlx::Postgres>,
    ),
    (StatusCode, String),
> {
    let a = auth::require_any_scope(&state.config, headers, &[scope]).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        headers,
        sentin8::shield::EvalTarget::new(scope),
    )
    .await?;
    let env_id = resolve_env(q, &a)?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_ctx(&mut conn, env_id, &a).await?;
    Ok((a, env_id, conn))
}

fn emit_relations_event(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    subject_type: &str,
    relation: &str,
    object_id: &str,
) {
    let envelope = PolicyUpdatedEnvelope {
        env_id,
        service: "sentin8:post".to_string(),
        policy_set_name: format!("{subject_type}/{relation}/{object_id}"),
        version: 1,
        enabled: true,
        mode: "enforced".to_string(),
    };
    let pool = pool.clone();
    tokio::spawn(async move {
        let _ = sentin8::bus::outbox::insert_policy_change_event(
            &pool,
            &envelope,
            "sentin8:sys:policy:relations:updated",
        )
        .await;
    });
}

/// `GET /v1/admin/relations` - list this service's relation tuples.
/// List relations.
#[utoipa::path(
    get,
    path = "/v1/admin/relations",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    responses(
        (status = 200, description = "OK", body = Vec<serde_json::Value>),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn list_relations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let (_a, env_id, mut conn) =
        admin_gate(&state, &headers, &q, "sentin8:post:policy:read").await?;
    let rows = sqlx::query(
        r#"SELECT subject_type, subject_id, relation, object_type, object_id, origin
             FROM sys.policy_relations
            WHERE service = 'sentin8:post' AND env_id = $1
            ORDER BY subject_type, subject_id, relation
            LIMIT 500"#,
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "subject_type": r.get::<String, _>("subject_type"),
                "subject_id": r.get::<String, _>("subject_id"),
                "relation": r.get::<String, _>("relation"),
                "object_type": r.get::<String, _>("object_type"),
                "object_id": r.get::<String, _>("object_id"),
                "origin": r.get::<String, _>("origin"),
            })
        })
        .collect();
    Ok(Json(items))
}

/// `PUT /v1/admin/relations` - upsert one relation tuple. Tenant
/// tuples carry `origin='tenant'`; the UNIQUE key dedupes re-writes.
/// Handle PUT relation.
#[utoipa::path(
    put,
    path = "/v1/admin/relations",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    request_body = PutRelationBody,
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn put_relation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    axum::Json(body): axum::Json<PutRelationBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let (a, env_id, mut conn) =
        admin_gate(&state, &headers, &q, "sentin8:post:policy:write").await?;
    let row: (Uuid,) = sqlx::query_as(
        r#"INSERT INTO sys.policy_relations
               (env_id, service, subject_type, subject_id, relation, object_type, object_id, origin)
           VALUES ($1, 'sentin8:post', $2, $3, $4, $5, $6, 'tenant')
           ON CONFLICT (env_id, subject_type, subject_id, relation, object_type, object_id) DO UPDATE
               SET service = 'sentin8:post', origin = 'tenant'
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(&body.subject_type)
    .bind(&body.subject_id)
    .bind(&body.relation)
    .bind(&body.object_type)
    .bind(&body.object_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    emit_relations_event(
        &state.pool,
        env_id,
        &body.subject_type,
        &body.relation,
        &body.object_id,
    );
    let _ = sqlx::query(
        r#"INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1, $2, $3, $4)"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(env_id)
    .bind("post")
    .bind(serde_json::json!({
        "action": "policy_relation.upserted",
        "resource_type": "policy_relation",
        "resource_id": row.0,
        "subject": format!("{}/{}", body.subject_type, body.subject_id),
        "relation": body.relation,
        "object": format!("{}/{}", body.object_type, body.object_id),
        "actor": a.claims.sub,
    }))
    .execute(&state.pool)
    .await;
    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"id": row.0, "status": "upserted"})),
    ))
}

/// `DELETE /v1/admin/relations` query/body - identifies the tuple.
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The deleterelationquery type.
pub struct DeleteRelationQuery {
    /// The subject type.
    pub subject_type: String,
    /// subject identifier.
    pub subject_id: String,
    /// The relation.
    pub relation: String,
    /// The object type.
    pub object_type: String,
    /// object identifier.
    pub object_id: String,
    #[serde(default)]
    /// target env identifier.
    pub target_env_id: Option<String>,
}

/// `DELETE /v1/admin/relations` - remove one relation tuple (tenant or
/// platform: env admins govern their env's graph; platform tuples are
/// re-seeded by enroll on the next `vertical init`).
/// Delete relation.
#[utoipa::path(
    delete,
    path = "/v1/admin/relations",
    params(DeleteRelationQuery),
    responses(
        (status = 204, description = "Done"),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn delete_relation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DeleteRelationQuery>,
) -> Result<StatusCode, (StatusCode, String)> {
    let tq = TargetEnvQuery {
        target_env_id: q.target_env_id.clone(),
    };
    let (a, env_id, mut conn) =
        admin_gate(&state, &headers, &tq, "sentin8:post:policy:write").await?;
    let result = sqlx::query(
        r#"DELETE FROM sys.policy_relations
            WHERE env_id = $1 AND service = 'sentin8:post'
              AND subject_type = $2 AND subject_id = $3
              AND relation = $4 AND object_type = $5 AND object_id = $6"#,
    )
    .bind(env_id)
    .bind(&q.subject_type)
    .bind(&q.subject_id)
    .bind(&q.relation)
    .bind(&q.object_type)
    .bind(&q.object_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "relation tuple not found".into()));
    }
    emit_relations_event(
        &state.pool,
        env_id,
        &q.subject_type,
        &q.relation,
        &q.object_id,
    );
    let _ = sqlx::query(
        r#"INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1, $2, $3, $4)"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(env_id)
    .bind("post")
    .bind(serde_json::json!({
        "action": "policy_relation.deleted",
        "resource_type": "policy_relation",
        "subject": format!("{}/{}", q.subject_type, q.subject_id),
        "relation": q.relation,
        "object": format!("{}/{}", q.object_type, q.object_id),
        "actor": a.claims.sub,
    }))
    .execute(&state.pool)
    .await;
    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/admin/relations/check` - Zanzibar-style dry-run :
/// is `subject` connected to `object` by `relation` (directly or through the
/// hierarchy)? Returns the tuple path + decision without side effects.
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The relationcheckquery type.
pub struct RelationCheckQuery {
    /// The subject type.
    pub subject_type: String,
    /// subject identifier.
    pub subject_id: String,
    /// The relation.
    pub relation: String,
    /// The object type.
    pub object_type: String,
    /// object identifier.
    pub object_id: String,
    #[serde(default)]
    /// target env identifier.
    pub target_env_id: Option<String>,
}

/// Check relation.
#[utoipa::path(
    get,
    path = "/v1/admin/relations/check",
    params(RelationCheckQuery),
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn check_relation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RelationCheckQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tq = TargetEnvQuery {
        target_env_id: q.target_env_id.clone(),
    };
    let (_a, env_id, mut _conn) =
        admin_gate(&state, &headers, &tq, "sentin8:post:policy:read").await?;
    // RLS: the slice read rides the admin_gate transaction (post DESIGN §5) -
    // `sys.policy_relations` is FORCE-RLS'd, so a bare-pool read is invisible.
    let slice: Vec<sentin8::shield::RelationRecord> = sqlx::query_as(
        r#"SELECT id, env_id, service, subject_type, subject_id, relation,
                  object_type, object_id, origin, created_at
             FROM sys.policy_relations
            WHERE env_id = $1 AND service = 'sentin8:post'
            ORDER BY created_at
            LIMIT 500"#,
    )
    .bind(env_id)
    .fetch_all(&mut *_conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Direct edge?
    let direct = slice.iter().any(|r| {
        r.subject_type == q.subject_type
            && r.subject_id == q.subject_id
            && r.relation == q.relation
            && r.object_type == q.object_type
            && r.object_id == q.object_id
    });
    // Transitive closure: BFS over subject→parent edges, any path to the
    // object via the requested relation grants membership (`in` semantics).
    let mut visited = std::collections::HashSet::new();
    let mut frontier = vec![format!("{}/{}", q.subject_type, q.subject_id)];
    let mut transitive = false;
    while let Some(cur) = frontier.pop() {
        if !visited.insert(cur.clone()) {
            continue;
        }
        for r in &slice {
            let subj = format!("{}/{}", r.subject_type, r.subject_id);
            let obj = format!("{}/{}", r.object_type, r.object_id);
            if subj == cur && r.relation == q.relation {
                if obj == format!("{}/{}", q.object_type, q.object_id) {
                    transitive = true;
                    break;
                }
                frontier.push(obj);
            }
        }
        if transitive {
            break;
        }
    }
    Ok(Json(serde_json::json!({
        "subject": format!("{}/{}", q.subject_type, q.subject_id),
        "relation": q.relation,
        "object": format!("{}/{}", q.object_type, q.object_id),
        "direct": direct,
        "transitive": transitive,
        "connected": direct || transitive,
        "tuple_count": slice.len(),
    })))
}

// ── Attributes admin API (/ - ABAC) ──────────────────────────

/// `PUT /v1/admin/attributes` body - one principal attribute.
#[derive(Deserialize, utoipa::ToSchema)]
/// The putattributebody type.
pub struct PutAttributeBody {
    /// subject identifier.
    pub subject_id: String,
    /// The attr key.
    pub attr_key: String,
    /// The attr value.
    pub attr_value: serde_json::Value,
}

/// `GET /v1/admin/attributes` - list principal attributes for one subject
/// (or all subjects when `subject_id` is omitted) in the target env.
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The listattributesquery type.
pub struct ListAttributesQuery {
    #[serde(default)]
    /// subject identifier.
    pub subject_id: Option<String>,
    #[serde(default)]
    /// target env identifier.
    pub target_env_id: Option<String>,
}

/// List attributes.
#[utoipa::path(
    get,
    path = "/v1/admin/attributes",
    params(ListAttributesQuery),
    responses(
        (status = 200, description = "OK", body = Vec<serde_json::Value>),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn list_attributes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListAttributesQuery>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let tq = TargetEnvQuery {
        target_env_id: q.target_env_id.clone(),
    };
    let (_a, env_id, mut conn) =
        admin_gate(&state, &headers, &tq, "sentin8:post:policy:read").await?;
    let rows = if let Some(sub) = &q.subject_id {
        sqlx::query(
            r#"SELECT subject_id, attr_key, attr_value, origin
                 FROM sys.policy_principal_attrs
                WHERE env_id = $1 AND subject_id = $2
                ORDER BY subject_id, attr_key
                LIMIT 500"#,
        )
        .bind(env_id)
        .bind(sub)
        .fetch_all(&mut *conn)
        .await
    } else {
        sqlx::query(
            r#"SELECT subject_id, attr_key, attr_value, origin
                 FROM sys.policy_principal_attrs
                WHERE env_id = $1
                ORDER BY subject_id, attr_key
                LIMIT 500"#,
        )
        .bind(env_id)
        .fetch_all(&mut *conn)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "subject_id": r.get::<String, _>("subject_id"),
                "attr_key": r.get::<String, _>("attr_key"),
                "attr_value": r.get::<serde_json::Value, _>("attr_value"),
                "origin": r.get::<String, _>("origin"),
            })
        })
        .collect();
    Ok(Json(items))
}

fn emit_attrs_event(pool: &sqlx::PgPool, env_id: Uuid, subject_id: &str, attr_key: &str) {
    let envelope = PolicyUpdatedEnvelope {
        env_id,
        service: "sentin8:post".to_string(),
        policy_set_name: format!("{subject_id}/{attr_key}"),
        version: 1,
        enabled: true,
        mode: "enforced".to_string(),
    };
    let pool = pool.clone();
    tokio::spawn(async move {
        let _ = sentin8::bus::outbox::insert_policy_change_event(
            &pool,
            &envelope,
            "sentin8:sys:policy:attrs:updated",
        )
        .await;
    });
}

/// `PUT /v1/admin/attributes` - upsert one principal attribute.
/// Values must be JSON scalars or arrays of scalars (Shield restricted
/// expressions cannot represent nested objects - 422 otherwise).
/// Handle PUT attribute.
#[utoipa::path(
    put,
    path = "/v1/admin/attributes",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    request_body = PutAttributeBody,
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn put_attribute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    axum::Json(body): axum::Json<PutAttributeBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let (a, env_id, mut conn) =
        admin_gate(&state, &headers, &q, "sentin8:post:policy:write").await?;
    if sentin8::shield::json_to_restricted_expr(&body.attr_value).is_none() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "attr_value must be a scalar or an array of scalars".into(),
        ));
    }
    sqlx::query(
        r#"INSERT INTO sys.policy_principal_attrs
               (env_id, subject_id, attr_key, attr_value, origin)
           VALUES ($1, $2, $3, $4, 'tenant')
           ON CONFLICT (env_id, subject_id, attr_key) DO UPDATE
               SET attr_value = EXCLUDED.attr_value, origin = 'tenant'"#,
    )
    .bind(env_id)
    .bind(&body.subject_id)
    .bind(&body.attr_key)
    .bind(&body.attr_value)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    emit_attrs_event(&state.pool, env_id, &body.subject_id, &body.attr_key);
    let _ = sqlx::query(
        r#"INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1, $2, $3, $4)"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(env_id)
    .bind("post")
    .bind(serde_json::json!({
        "action": "policy_attribute.upserted",
        "resource_type": "policy_attribute",
        "subject_id": body.subject_id,
        "attr_key": body.attr_key,
        "actor": a.claims.sub,
    }))
    .execute(&state.pool)
    .await;
    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"status": "upserted"})),
    ))
}

/// `DELETE /v1/admin/attributes` - remove one principal attribute.
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The deleteattributequery type.
pub struct DeleteAttributeQuery {
    /// subject identifier.
    pub subject_id: String,
    /// The attr key.
    pub attr_key: String,
    #[serde(default)]
    /// target env identifier.
    pub target_env_id: Option<String>,
}

/// Delete attribute.
#[utoipa::path(
    delete,
    path = "/v1/admin/attributes",
    params(DeleteAttributeQuery),
    responses(
        (status = 204, description = "Done"),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn delete_attribute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DeleteAttributeQuery>,
) -> Result<StatusCode, (StatusCode, String)> {
    let tq = TargetEnvQuery {
        target_env_id: q.target_env_id.clone(),
    };
    let (a, env_id, mut conn) =
        admin_gate(&state, &headers, &tq, "sentin8:post:policy:write").await?;
    let result = sqlx::query(
        "DELETE FROM sys.policy_principal_attrs WHERE env_id = $1 AND subject_id = $2 AND attr_key = $3",
    )
    .bind(env_id)
    .bind(&q.subject_id)
    .bind(&q.attr_key)
    .execute(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "attribute not found".into()));
    }
    emit_attrs_event(&state.pool, env_id, &q.subject_id, &q.attr_key);
    let _ = sqlx::query(
        r#"INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1, $2, $3, $4)"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(env_id)
    .bind("post")
    .bind(serde_json::json!({
        "action": "policy_attribute.deleted",
        "resource_type": "policy_attribute",
        "subject_id": q.subject_id,
        "attr_key": q.attr_key,
        "actor": a.claims.sub,
    }))
    .execute(&state.pool)
    .await;
    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}
// ── RFW POST-alias row actions ( - Dash 28.14; renderer is POST-only,
// ) ─────────────────────────────────────────

/// Shared body for the mode-flip aliases: `{"policy_set_name": "…", "enabled": bool}`.
#[derive(Deserialize, utoipa::ToSchema)]
/// The policymodebody type.
pub struct PolicyModeBody {
    /// The policy set name.
    pub policy_set_name: String,
    #[serde(default)]
    /// The enabled.
    pub enabled: Option<bool>,
}

/// Flip mode/enabled on a policy set and emit the hot-reload event. Used by
/// the RFW row actions (enforce → `mode='enforced'`; shadow → `mode='shadow'`;
/// disable → `enabled=false`).
async fn flip_policy_mode(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    mode: Option<&str>,
    enabled_override: Option<bool>,
    body: PolicyModeBody,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a =
        auth::require_any_scope(&state.config, &headers, &["sentin8:post:policy:write"]).await?;
    let env_id = resolve_env(&q, &a)?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_ctx(&mut conn, env_id, &a).await?;
    let (new_mode, new_enabled) = match (mode, enabled_override) {
        (Some("enforced"), _) => ("enforced".to_string(), body.enabled.unwrap_or(true)),
        (Some("shadow"), _) => ("shadow".to_string(), body.enabled.unwrap_or(true)),
        (_, Some(false)) => ("shadow".to_string(), false),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "no mode/enabled change requested".into(),
            ))
        }
    };
    // Tenant rows flip freely; platform rows are enroll-managed for MODE only
    // (shadow→enforced promotion is the ops lever - allowed; origin stays).
    let row: (i32, String, bool) = sqlx::query_as(
        r#"UPDATE sys.policy_sets
              SET mode = $3, enabled = COALESCE($4, enabled), version = version + 1, updated_at = now()
            WHERE service = 'sentin8:post' AND env_id = $1 AND policy_set_name = $2
        RETURNING version, mode, enabled"#,
    )
    .bind(env_id)
    .bind(&body.policy_set_name)
    .bind(&new_mode)
    .bind(new_enabled)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, format!("policy set '{}' not found", body.policy_set_name)))?;
    let (version, out_mode, out_enabled) = row;
    if let Err(e) = emit_policy_event(
        &state.pool,
        env_id,
        "sentin8:post",
        &body.policy_set_name,
        version,
        out_enabled,
        &out_mode,
    )
    .await
    {
        tracing::warn!(error = %e, "policy flip event emit failed");
    }
    let _ = sqlx::query(
        r#"INSERT INTO audit_journal (id, env_id, action, details) VALUES ($1, $2, $3, $4)"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(env_id)
    .bind("post")
    .bind(serde_json::json!({
        "action": "policy_set.mode_flipped",
        "resource_type": "policy_set",
        "resource_id": body.policy_set_name,
        "mode": out_mode,
        "enabled": out_enabled,
        "actor": a.claims.sub,
    }))
    .execute(&state.pool)
    .await;
    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({
        "policy_set_name": body.policy_set_name,
        "mode": out_mode,
        "enabled": out_enabled,
        "version": version,
    })))
}

/// `POST /v1/admin/policy-sets/enforce` - promote a set to enforced.
/// Handle admin enforce policy set.
#[utoipa::path(
    post,
    path = "/v1/admin/policy-sets/enforce",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    request_body = PolicyModeBody,
    responses(
        (status = 204, description = "Done"),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn admin_enforce_policy_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<PolicyModeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    flip_policy_mode(
        State(state),
        headers,
        Query(q),
        Some("enforced"),
        None,
        body,
    )
    .await
}

/// `POST /v1/admin/policy-sets/shadow` - demote a set to shadow (rollback).
/// Handle admin shadow policy set.
#[utoipa::path(
    post,
    path = "/v1/admin/policy-sets/shadow",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    request_body = PolicyModeBody,
    responses(
        (status = 204, description = "Done"),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn admin_shadow_policy_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<PolicyModeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    flip_policy_mode(State(state), headers, Query(q), Some("shadow"), None, body).await
}

/// `POST /v1/admin/policy-sets/disable` - disable a set (no-match → deny for
/// its actions; use `shadow` for pure observation-off).
/// Handle admin disable policy set.
#[utoipa::path(
    post,
    path = "/v1/admin/policy-sets/disable",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    request_body = PolicyModeBody,
    responses(
        (status = 204, description = "Done"),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn admin_disable_policy_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<PolicyModeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    flip_policy_mode(State(state), headers, Query(q), None, Some(false), body).await
}

// ── RFW renderer helpers ─────────────────────
// The RFW renderer only supports POST and submits row
// actions with an empty body, so the UI mutations get POST aliases whose
// target is identified by the PATH. CLI callers keep the canonical verbs.

/// Policy text / schema size caps - mirrors the shared admin
/// module (`sentin8::shield::admin::MAX_POLICY_TEXT_BYTES`); post's local
/// copy applies the same guardrail.
const MAX_POLICY_TEXT_BYTES: usize = 64 * 1024;
const MAX_SCHEMA_TEXT_BYTES: usize = 64 * 1024;

/// Normalize the optional Shield schema from a request body: an empty or
/// whitespace-only string means "no schema" (the RFW form renderer submits
/// `""` for untouched optional textareas - ).
fn normalize_schema(schema: Option<&str>) -> Option<&str> {
    schema.filter(|s| !s.trim().is_empty())
}

fn check_text_caps(policies: &str, schema: Option<&str>) -> Result<(), (StatusCode, String)> {
    if policies.len() > MAX_POLICY_TEXT_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "policy text exceeds {} KiB (got {} bytes)",
                MAX_POLICY_TEXT_BYTES / 1024,
                policies.len()
            ),
        ));
    }
    if let Some(schema) = schema {
        if schema.len() > MAX_SCHEMA_TEXT_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "schema text exceeds {} KiB (got {} bytes)",
                    MAX_SCHEMA_TEXT_BYTES / 1024,
                    schema.len()
                ),
            ));
        }
    }
    Ok(())
}

/// `POST /v1/admin/policy-sets` - create a tenant policy set (name in body).
/// Reuses the local PUT core (validation + tenant origin + event + audit),
/// then redirects the RFW renderer to the editor page.
#[derive(Deserialize, utoipa::ToSchema)]
/// The createpolicysetbody type.
pub struct CreatePolicySetBody {
    /// The policy set name.
    pub policy_set_name: String,
    /// The policies.
    pub policies: String,
    #[serde(default)]
    /// The description.
    pub description: String,
    #[serde(default)]
    /// The schema.
    pub schema: Option<String>,
    #[serde(default)]
    /// The mode.
    pub mode: Option<String>,
}

/// Create policy set.
#[utoipa::path(
    post,
    path = "/v1/admin/policy-sets",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    request_body = CreatePolicySetBody,
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn create_policy_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    axum::Json(body): axum::Json<CreatePolicySetBody>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    check_text_caps(&body.policies, normalize_schema(body.schema.as_deref()))?;
    let name = body.policy_set_name.trim().to_string();
    if name.is_empty()
        || name.len() > 128
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "policy_set_name must be 1-128 chars of [A-Za-z0-9_-]".into(),
        ));
    }
    let put = PutPolicySetBody {
        policies: body.policies,
        description: body.description,
        schema: body.schema,
        enabled: None,
        mode: body.mode,
    };
    let (status, Json(payload)) = put_policy_set(
        State(state),
        headers,
        Path(name.clone()),
        Query(q),
        axum::Json(put),
    )
    .await?;
    Ok(match status {
        StatusCode::CREATED => axum::Json(serde_json::json!({
            "response_type": "redirect",
            "route": format!("policy-sets/{name}/edit"),
            "policy_set": payload,
        })),
        _ => axum::Json(serde_json::json!({
            "response_type": "error",
            "message": payload,
        })),
    }
    .into_response())
}

/// `POST /v1/admin/policy-sets/{name}/save` - PUT alias for the RFW renderer.
/// Handle save policy set.
#[utoipa::path(
    post,
    path = "/v1/admin/policy-sets/{name}/save",
    params(
        ("name" = String, Path, description = "Policy set name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    request_body = PutPolicySetBody,
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn save_policy_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<TargetEnvQuery>,
    body: axum::Json<PutPolicySetBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    check_text_caps(&body.policies, normalize_schema(body.schema.as_deref()))?;
    put_policy_set(State(state), headers, Path(name), Query(q), body).await
}

/// `POST /v1/admin/policy-sets/{name}/{action}` - path-param row-action
/// dispatcher (enforce | shadow | disable | delete). One route shape serves
/// all four actions (axum's matchit router cannot register `{name}/delete`
/// next to `{name}/{action}` without a conflict).
/// Handle admin path action policy set.
#[utoipa::path(
    post,
    path = "/v1/admin/policy-sets/{name}/{action}",
    params(
        ("name" = String, Path, description = "Policy set name"),
        ("action" = String, Path, description = "Row action (enforce | shadow | disable | delete)"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn admin_path_action_policy_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, action)): Path<(String, String)>,
    Query(q): Query<TargetEnvQuery>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    if action == "delete" {
        let status = delete_policy_set(State(state), headers, Path(name), Query(q)).await?;
        return Ok(status.into_response());
    }
    let mode = match action.as_str() {
        "enforce" => Some("enforced"),
        "shadow" => Some("shadow"),
        "disable" => None,
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("unknown policy-set action '{action}'"),
            ))
        }
    };
    flip_policy_mode(
        State(state),
        headers,
        Query(q),
        mode,
        None,
        PolicyModeBody {
            policy_set_name: name,
            enabled: None,
        },
    )
    .await
    .map(|Json(v)| Json(v).into_response())
}

/// `POST /v1/admin/relations/{id}/delete` - row-action alias.
/// `id` is the colon-joined tuple the RFW list emits
/// (`subject_type:subject_id:relation:object_type:object_id`); parsed
/// back-first (the last three segments are relation/object_type/object_id,
/// the first is subject_type, the middle rest is subject_id - tolerant of
/// colons inside subject ids).
/// Handle admin delete relation path.
#[utoipa::path(
    post,
    path = "/v1/admin/relations/{id}/delete",
    params(
        ("id" = String, Path, description = "Relation id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 204, description = "Done"),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn admin_delete_relation_path(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<TargetEnvQuery>,
) -> Result<StatusCode, (StatusCode, String)> {
    let parts: Vec<&str> = id.split(':').collect();
    if parts.len() < 5 {
        return Err((
            StatusCode::BAD_REQUEST,
            "relation id must be subject_type:subject_id:relation:object_type:object_id".into(),
        ));
    }
    let (subject_type, object_type, object_id, relation) = (
        parts[0],
        parts[parts.len() - 2],
        parts[parts.len() - 1],
        parts[parts.len() - 3],
    );
    let subject_id = parts[1..parts.len() - 3].join(":");
    let dq = DeleteRelationQuery {
        subject_type: subject_type.to_string(),
        subject_id,
        relation: relation.to_string(),
        object_type: object_type.to_string(),
        object_id: object_id.to_string(),
        target_env_id: q.target_env_id.clone(),
    };
    delete_relation(State(state), headers, Query(dq)).await
}

/// `POST /v1/admin/attributes/{id}/delete` - row-action alias.
/// `id` is `subject_id:attr_key` as emitted by the RFW list; splitn(2)
/// keeps any colons inside the attribute key.
/// Handle admin delete attribute path.
#[utoipa::path(
    post,
    path = "/v1/admin/attributes/{id}/delete",
    params(
        ("id" = String, Path, description = "Attribute id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 204, description = "Done"),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn admin_delete_attribute_path(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<TargetEnvQuery>,
) -> Result<StatusCode, (StatusCode, String)> {
    let (subject_id, attr_key) = id.split_once(':').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "attribute id must be subject_id:attr_key".into(),
        )
    })?;
    let dq = DeleteAttributeQuery {
        subject_id: subject_id.to_string(),
        attr_key: attr_key.to_string(),
        target_env_id: q.target_env_id.clone(),
    };
    delete_attribute(State(state), headers, Query(dq)).await
}

/// `GET /v1/admin/policy-decisions` - deny / would-deny feed for the UI
/// . Reads the shared audit trail rows the runtime writes
/// (`event->>'action' IN ('policy.deny','policy.would_deny')`).
/// List policy decisions.
#[utoipa::path(
    get,
    path = "/v1/admin/policy-decisions",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    responses(
        (status = 200, description = "Recent decision log (policy.deny / would_deny rows)", body = Vec<serde_json::Value>),
        (status = 403, description = "Caller lacks the policy scope"),
    ),
    security(("sentin8:post:policy:read" = [])),
    tag = "policy",
)]
pub async fn list_policy_decisions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let a = auth::require_any_scope(&state.config, &headers, &["sentin8:post:policy:read"]).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:policy:read"),
    )
    .await?;
    let env_id = resolve_env(&q, &a)?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    set_ctx(&mut conn, env_id, &a).await?;
    let rows = sqlx::query(
        r#"SELECT id, created_at, event
             FROM audit_events
            WHERE env_id = $1
              AND service = 'post'
              AND (event->>'action' = 'policy.deny' OR event->>'action' = 'policy.would_deny')
            ORDER BY created_at DESC
            LIMIT 200"#,
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let event: serde_json::Value = r.get("event");
            serde_json::json!({
                "id": r.get::<uuid::Uuid, _>("id"),
                "timestamp": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
                "decision": event.get("action").cloned().unwrap_or(serde_json::json!("unknown")),
                "action_id": event.get("action_id").cloned().unwrap_or(serde_json::json!("")),
                "reason": event.get("reason").cloned().unwrap_or(serde_json::json!("")),
                "policy_set": event.get("policy_set").cloned().unwrap_or(serde_json::json!("")),
                "subject": event.get("subject").cloned().unwrap_or(serde_json::json!("")),
                "enforced": event.get("enforced").cloned().unwrap_or(serde_json::json!(false)),
            })
        })
        .collect();
    Ok(Json(items))
}

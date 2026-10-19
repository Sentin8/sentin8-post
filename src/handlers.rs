// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Post HTTP handlers - messages, gateways, DLQ.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::admin_ui::TargetEnvQuery;
use crate::auth;
use crate::config::PostConfig;

#[derive(Clone)]
/// app state.
pub struct AppState {
    /// The config.
    pub config: Arc<PostConfig>,
    /// The pool.
    pub pool: sqlx::PgPool,
    /// Shield engine ( pilot - design stage 0). Scope checks
    /// remain primary; policy adds the attribute layer.
    /// The policy.
    pub policy: Arc<crate::policy::Engine>,
    /// Boot-loaded workload registry (auth DESIGN §4.3f) - the cert-first
    /// handler gate's authorization record (sys's `sys-post` pusher,
    /// any enrolled M2M caller).
    pub workload_registry: sentin8::auth::workload_registry::WorkloadMap,
}

// ── Health ─────────────────────────────────────────────────────────────

/// Handle health.
#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "Liveness (version, build, active connections)", body = sentin8::middleware::health::LiveHealth),
    ),
    security(),
    tag = "meta",
)]
pub async fn health(State(_state): State<AppState>) -> Json<serde_json::Value> {
    let mut payload = serde_json::json!({"status": "ok", "service": "post", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash()});
    if let Some(n) = sentin8::middleware::traffic_counter::process_active_connections() {
        payload["active_connections"] = serde_json::json!(n);
    }
    Json(payload)
}

// ── Messages ───────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
/// The listmessagesquery type.
pub struct ListMessagesQuery {
    #[allow(dead_code)]
    #[serde(default)]
    /// The message type.
    pub message_type: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    /// The status.
    pub status: Option<String>,
    #[serde(default)]
    /// The limit.
    pub limit: Option<i64>,
    /// When `mine=true`, filter to messages where `recipient_user_id` matches
    /// the caller's Auth user UUID. Used by customer-facing apps (eBank) so
    /// users only see their own messages, not all org/env messages.
    #[serde(default)]
    /// The mine.
    pub mine: Option<bool>,
    /// When `unread=true`, filter to messages where `read_at IS NULL`.
    #[serde(default)]
    /// The unread.
    pub unread: Option<bool>,
}

#[derive(Serialize, ToSchema)]
/// The messagesummary type.
pub struct MessageSummary {
    /// Identifier.
    pub id: Uuid,
    /// The stream family.
    pub stream_family: String,
    /// The message type.
    pub message_type: String,
    /// The category.
    pub category: String,
    /// The priority.
    pub priority: String,
    /// recipient user identifier.
    pub recipient_user_id: Option<Uuid>,
    /// The recipient email.
    pub recipient_email: Option<String>,
    /// The subject.
    pub subject: String,
    /// The delivered.
    pub delivered: bool,
    /// The delivered at.
    pub delivered_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The read.
    pub read: bool,
    /// The read at.
    pub read_at: Option<chrono::DateTime<chrono::Utc>>,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/messages` - list messages in the caller's org/env.
#[utoipa::path(
    post,
    operation_id = "message.send",
    path = "/v1/send",
    request_body = SendMessageRequest,
    responses(
        (status = 201, description = "Message queued", body = SendMessageResponse),
        (status = 403, description = "Missing post:write scope"),
    ),
    security(("sentin8:post:write" = [])),
    tag = "post",
)]
/// Send message.
pub async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:write"),
    )
    .await?;
    let env_id = a.env_id();

    // DBX : `stream_family` (the producer service identity) is derived
    // from the verified token - never caller-supplied. M2M `sub` is the DCR
    // client id; for user tokens fall back to the subject.
    let stream_family = a.claims.sub.clone();

    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("pool: {e}")))?;
    let _ = sqlx::query(
        "SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, $2)",
    )
    .bind(env_id)
    .bind(&stream_family)
    .execute(&mut *conn)
    .await;
    let row: (uuid::Uuid,) = sqlx::query_as(
        r#"INSERT INTO inbox
           (env_id, stream_family, message_type, category, priority,
            recipient_user_id, recipient_email, subject, body, body_format, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(&stream_family)
    .bind(&req.message_type)
    .bind(req.category.as_deref().unwrap_or("system"))
    .bind(req.priority.as_deref().unwrap_or("normal"))
    .bind(req.recipient_user_id)
    .bind(&req.recipient_email)
    .bind(&req.subject)
    .bind(&req.body)
    .bind(req.body_format.as_deref().unwrap_or("text"))
    .bind(&req.metadata)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("send: {e}")))?;

    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("commit: {e}")))?;
    Ok(Json(SendMessageResponse {
        id: row.0,
        env_id,
        status: "queued".to_string(),
    }))
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
/// Request body for sendmessage.
pub struct SendMessageRequest {
    /// The message type.
    pub message_type: String,
    /// The category.
    pub category: Option<String>,
    /// The priority.
    pub priority: Option<String>,
    /// recipient user identifier.
    pub recipient_user_id: Option<uuid::Uuid>,
    /// The recipient email.
    pub recipient_email: Option<String>,
    /// The subject.
    pub subject: String,
    /// The body.
    pub body: String,
    /// The body format.
    pub body_format: Option<String>,
    #[serde(default = "default_metadata")]
    /// The metadata.
    pub metadata: serde_json::Value,
}

fn default_metadata() -> serde_json::Value {
    serde_json::json!({})
}

#[derive(Serialize, utoipa::ToSchema)]
/// Response payload for sendmessage.
pub struct SendMessageResponse {
    /// Identifier.
    pub id: uuid::Uuid,
    /// env identifier.
    pub env_id: uuid::Uuid,
    /// The status.
    pub status: String,
}

#[utoipa::path(
    get,
    operation_id = "message.list",
    path = "/v1/messages",
    params(("message_type" = Option<String>, Query), ("status" = Option<String>, Query), ("limit" = Option<i64>, Query), ("mine" = Option<bool>, Query), ("unread" = Option<bool>, Query)),
    responses(
        (status = 200, description = "List of messages", body = [MessageSummary]),
        (status = 403, description = "Missing post:read scope"),
    ),
    security(("sentin8:post:read" = [])),
    tag = "post",
)]
/// List messages.
pub async fn list_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListMessagesQuery>,
) -> Result<Json<Vec<MessageSummary>>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:read"),
    )
    .await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(a.env_id())
        .execute(&mut *conn)
        .await;
    let limit = q.limit.unwrap_or(100).min(500);
    let unread_only = q.unread.unwrap_or(false);

    // When mine=true, filter by the caller's user ID (customer-facing apps).
    let my_user_id = if q.mine.unwrap_or(false) {
        a.claims.sentin8_auth_user_uuid()
    } else {
        None
    };

    // Build the read_at filter clause.
    let read_clause = if unread_only {
        " AND read_at IS NULL"
    } else {
        ""
    };

    let rows = if let Some(uid) = my_user_id {
        let query_str = format!(
            r#"SELECT id, stream_family, message_type, category, priority,
                      recipient_user_id, recipient_email, subject, delivered,
                      delivered_at, read_at, created_at
                 FROM inbox
                WHERE env_id = $1 AND recipient_user_id = $2{read_clause}
                ORDER BY created_at DESC
                LIMIT $3"#
        );
        sqlx::query(&query_str)
            .bind(a.env_id())
            .bind(uid)
            .bind(limit)
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    } else {
        let query_str = format!(
            r#"SELECT id, stream_family, message_type, category, priority,
                      recipient_user_id, recipient_email, subject, delivered,
                      delivered_at, read_at, created_at
                 FROM inbox
                WHERE env_id = $1{read_clause}
                ORDER BY created_at DESC
                LIMIT $2"#
        );
        sqlx::query(&query_str)
            .bind(a.env_id())
            .bind(limit)
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    let messages: Vec<MessageSummary> = rows
        .iter()
        .map(|r| MessageSummary {
            id: r.get("id"),
            stream_family: r.get("stream_family"),
            message_type: r.get("message_type"),
            category: r.get("category"),
            priority: r.get("priority"),
            recipient_user_id: r.get("recipient_user_id"),
            recipient_email: r.get("recipient_email"),
            subject: r.get("subject"),
            delivered: r.get("delivered"),
            delivered_at: r.get("delivered_at"),
            read: r
                .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("read_at")
                .ok()
                .flatten()
                .is_some(),
            read_at: r.try_get("read_at").ok().flatten(),
            created_at: r.get("created_at"),
        })
        .collect();
    Ok(Json(messages))
}

/// `GET /v1/messages/{id}` - message detail with all delivery attempts.
#[utoipa::path(
    get,
    operation_id = "message.get",
    path = "/v1/messages/{id}",
    params(("id" = Uuid, Path, description = "Message ID")),
    responses(
        (status = 200, description = "Message detail"),
        (status = 404, description = "Message not found"),
        (status = 403, description = "Missing post:read scope"),
    ),
    security(("sentin8:post:read" = [])),
    tag = "post",
)]
/// Fetch message.
pub async fn get_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:read"),
    )
    .await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(a.env_id())
        .execute(&mut *conn)
        .await;
    let row = sqlx::query(
        r#"SELECT id, stream_family, message_type, category, priority,
                  recipient_user_id, recipient_email, recipient_phone,
                  subject, body, body_format, metadata,
                  delivered, delivered_at, read_at, created_at
             FROM inbox
            WHERE id = $1 AND env_id = $2"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = match row {
        Some(r) => r,
        None => return Err((StatusCode::NOT_FOUND, "message not found".into())),
    };

    // Fetch delivery attempts.
    let deliveries = sqlx::query(
        r#"SELECT id, channel, status, gateway_message_id, retry_count,
                  max_retries, error, next_retry_at, delivered_at, created_at
             FROM deliveries
            WHERE inbox_id = $1
            ORDER BY created_at"#,
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let deliveries: Vec<serde_json::Value> = deliveries
        .iter()
        .map(|d| {
            let id: Uuid = d.get("id");
            let channel: String = d.get("channel");
            let status: String = d.get("status");
            let gateway_message_id: Option<String> = d.get("gateway_message_id");
            let retry_count: i32 = d.get("retry_count");
            let error: Option<String> = d.get("error");
            let delivered_at: Option<chrono::DateTime<chrono::Utc>> = d.get("delivered_at");
            let created_at: chrono::DateTime<chrono::Utc> = d.get("created_at");
            serde_json::json!({
                "id": id,
                "channel": channel,
                "status": status,
                "gateway_message_id": gateway_message_id,
                "retry_count": retry_count,
                "error": error,
                "delivered_at": delivered_at,
                "created_at": created_at,
            })
        })
        .collect();

    let message = {
        let id: Uuid = row.get("id");
        let stream_family: String = row.get("stream_family");
        let message_type: String = row.get("message_type");
        let category: String = row.get("category");
        let priority: String = row.get("priority");
        let recipient_user_id: Option<Uuid> = row.get("recipient_user_id");
        let recipient_email: Option<String> = row.get("recipient_email");
        let recipient_phone: Option<String> = row.get("recipient_phone");
        let subject: String = row.get("subject");
        let body: String = row.get("body");
        let body_format: String = row.get("body_format");
        let metadata: serde_json::Value = row.get("metadata");
        let delivered: bool = row.get("delivered");
        let delivered_at: Option<chrono::DateTime<chrono::Utc>> = row.get("delivered_at");
        let read_at: Option<chrono::DateTime<chrono::Utc>> = row.try_get("read_at").ok().flatten();
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        serde_json::json!({
            "id": id,
            "stream_family": stream_family,
            "message_type": message_type,
            "category": category,
            "priority": priority,
            "recipient_user_id": recipient_user_id,
            "recipient_email": recipient_email,
            "recipient_phone": recipient_phone,
            "subject": subject,
            "body": body,
            "body_format": body_format,
            "metadata": metadata,
            "delivered": delivered,
            "delivered_at": delivered_at,
            "read": read_at.is_some(),
            "read_at": read_at,
            "created_at": created_at,
            "deliveries": deliveries,
        })
    };
    Ok(Json(message))
}

/// `POST /v1/messages/{id}/read` - mark a message as read.
///
/// Sets `read_at = now` on the message. Idempotent - a second call is a
/// no-op. Used by customer-facing apps (eBank) when the user opens a
/// message, so the notification badge unread count decreases. The read
/// receipt `sentin8:post:notification:read` is emitted as a local
/// `post.outbox` row in the SAME transaction as the read update
/// (post DESIGN §4) - exactly once with the domain change; the shell
/// relay produces it to Bus (§6.7).
#[utoipa::path(
    post,
    operation_id = "message.mark-read",
    path = "/v1/messages/{id}/read",
    params(("id" = Uuid, Path, description = "Message ID")),
    responses(
        (status = 200, description = "Message marked as read"),
        (status = 404, description = "Message not found"),
        (status = 403, description = "Missing post:read scope"),
    ),
    security(("sentin8:post:read" = [])),
    tag = "post",
)]
/// Handle mark message read.
pub async fn mark_message_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:read"),
    )
    .await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(a.env_id())
        .execute(&mut *conn)
        .await;

    // Look up the recipient_user_id before marking read - the read
    // receipt's user_id comes from the row (email-only messages have no
    // user badge to update and emit nothing).
    let recipient_user_id: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT recipient_user_id FROM inbox
            WHERE id = $1 AND env_id = $2"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Mark read and capture the exact read_at for the receipt payload.
    let read_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        r#"UPDATE inbox SET read_at = COALESCE(read_at, now())
            WHERE id = $1 AND env_id = $2
            RETURNING read_at"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .flatten();

    // Read receipt - `sentin8:post:notification:read` (post DESIGN §4):
    // the unread count is computed AFTER the update on the SAME connection
    // (tenant context is transaction-local - a bare-pool COUNT sees no rows
    // under FORCE RLS). The outbox row commits atomically with the read
    // update and the shell relay produces it (§6.7). Best-effort: a failed
    // emission delays the badge update, never blocks the read.
    if let Some(uid) = recipient_user_id {
        let unread_count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM inbox
                WHERE env_id = $1 AND recipient_user_id = $2
                  AND read_at IS NULL"#,
        )
        .bind(a.env_id())
        .bind(uid)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or(0);

        let payload = serde_json::json!({
            "user_id": uid,
            "notification_id": id,
            "env_id": a.env_id(),
            "read_at": read_at.unwrap_or_else(chrono::Utc::now),
            "unread_count": unread_count,
        });
        // ENV CONTRACT: the outbox row carries SYSTEM_ENV_ID - the shell's
        // relay produces with post's M2M token, which is bound to the system
        // env; a caller-env row makes Bus reject the produce with 403
        // (cross-tenant) and the relay would hot-loop it forever. The target
        // env rides the payload (`env_id`). The caller→system context swap
        // is safe here: this is the LAST write in the transaction and no
        // further statement reads tenant-filtered rows (sys `audit_tx`
        // fan-out pattern).
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(sentin8::config::SYSTEM_ENV_ID)
            .execute(&mut *conn)
            .await;
        if let Err(e) = sentin8::bus::outbox::insert_outbox_row_with_publisher(
            &mut *conn,
            sentin8::config::SYSTEM_ENV_ID,
            "notifications",
            "sentin8:post:notification:read",
            &payload,
            None,
            Some(a.claims.sub.as_str()),
        )
        .await
        {
            tracing::warn!(error = %e, message_id = %id, "post: read-receipt outbox insert failed");
        }
    }

    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("commit: {e}")))?;
    Ok(Json(serde_json::json!({ "id": id, "read": true })))
}

/// `GET /v1/messages/{id}/content` - message content (subject + body only).
/// `GET /v1/messages/{id}/content` - raw message content.
#[utoipa::path(
    get,
    operation_id = "message.content",
    path = "/v1/messages/{id}/content",
    params(("id" = Uuid, Path, description = "Message ID")),
    responses(
        (status = 200, description = "Message content"),
        (status = 404, description = "Message not found"),
        (status = 403, description = "Missing post:read scope"),
    ),
    security(("sentin8:post:read" = [])),
    tag = "post",
)]
/// Fetch message content.
pub async fn get_message_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:read"),
    )
    .await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(a.env_id())
        .execute(&mut *conn)
        .await;
    let row = sqlx::query(
        r#"SELECT subject, body, body_format FROM inbox WHERE id = $1 AND env_id = $2"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row = match row {
        Some(r) => r,
        None => return Err((StatusCode::NOT_FOUND, "message not found".into())),
    };
    let subject: String = row.get("subject");
    let body: String = row.get("body");
    let body_format: String = row.get("body_format");
    Ok(Json(serde_json::json!({
        "subject": subject,
        "body": body,
        "body_format": body_format,
    })))
}

// ── DLQ ────────────────────────────────────────────────────────────────

/// `GET /v1/dlq` - list dead-lettered deliveries.
/// `GET /v1/dlq` - list dead-letter queue entries.
#[utoipa::path(
    get,
    operation_id = "dlq.list",
    path = "/v1/dlq",
    responses(
        (status = 200, description = "DLQ entries"),
        (status = 403, description = "Missing post:read scope"),
    ),
    security(("sentin8:post:read" = [])),
    tag = "post",
)]
/// List dlq.
pub async fn list_dlq(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:read"),
    )
    .await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(a.env_id())
        .execute(&mut *conn)
        .await;
    let rows = sqlx::query(
        r#"SELECT d.id, d.inbox_id, d.channel, d.error, d.retry_count, d.created_at,
                  i.subject, i.message_type, i.stream_family
             FROM dlq d
             JOIN inbox i ON i.id = d.inbox_id
            WHERE d.env_id = $1
            ORDER BY d.created_at DESC
            LIMIT 100"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let inbox_id: Uuid = r.get("inbox_id");
            let channel: String = r.get("channel");
            let error: String = r.get("error");
            let retry_count: i32 = r.get("retry_count");
            let subject: String = r.get("subject");
            let message_type: String = r.get("message_type");
            let stream_family: String = r.get("stream_family");
            let created_at: chrono::DateTime<chrono::Utc> = r.get("created_at");
            serde_json::json!({
                "id": id,
                "inbox_id": inbox_id,
                "channel": channel,
                "error": error,
                "retry_count": retry_count,
                "subject": subject,
                "message_type": message_type,
                "stream_family": stream_family,
                "created_at": created_at,
            })
        })
        .collect();
    Ok(Json(items))
}

/// `POST /v1/dlq/{id}/replay` - replay a dead-lettered delivery.
/// `POST /v1/dlq/{id}/replay` - replay a DLQ entry.
#[utoipa::path(
    post,
    operation_id = "message.replay",
    path = "/v1/dlq/{id}/replay",
    params(("id" = Uuid, Path, description = "DLQ entry ID")),
    responses(
        (status = 200, description = "DLQ entry replayed"),
        (status = 404, description = "DLQ entry not found"),
        (status = 403, description = "Missing post:write scope"),
    ),
    security(("sentin8:post:write" = [])),
    tag = "post",
)]
/// Handle replay dlq.
pub async fn replay_dlq(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:write"),
    )
    .await?;
    // Reset the delivery to pending and remove from DLQ.
    let result = sqlx::query(r#"DELETE FROM dlq WHERE id = $1 RETURNING inbox_id, channel"#)
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(row) = result {
        let inbox_id: Uuid = row.get("inbox_id");
        let channel: String = row.get("channel");
        // Reset the inbox row for re-delivery.
        let _ =
            sqlx::query("UPDATE inbox SET delivered = false, delivered_at = NULL WHERE id = $1")
                .bind(inbox_id)
                .execute(&state.pool)
                .await;
        // Reset any failed delivery rows for this channel.
        let _ = sqlx::query(
            r#"UPDATE deliveries SET status = 'pending', retry_count = 0, error = NULL, next_retry_at = now()
                WHERE inbox_id = $1 AND channel = $2"#,
        )
        .bind(inbox_id)
        .bind(&channel)
        .execute(&state.pool)
        .await;
        tracing::info!(dlq_id = %id, inbox_id = %inbox_id, channel = %channel, "post: DLQ replay requested");
    } else {
        // Unknown id - 404, not a silent OK (post DESIGN §4.6).
        return Err((StatusCode::NOT_FOUND, format!("dlq entry {id} not found")));
    }
    Ok(StatusCode::OK)
}

// ── Gateways ───────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
/// Request body for creategateway.
pub struct CreateGatewayRequest {
    /// The scope.
    pub scope: String,
    /// The channel.
    pub channel: String,
    /// The provider.
    pub provider: String,
    /// The config.
    pub config: serde_json::Value,
    /// Whether enabled.
    pub is_enabled: bool,
}

/// `GET /v1/gateways` - list gateway configs.
#[utoipa::path(
    get,
    operation_id = "gateway.list",
    path = "/v1/gateways",
    responses(
        (status = 200, description = "List of gateways"),
        (status = 403, description = "Missing post:read scope"),
    ),
    security(("sentin8:post:read" = [])),
    tag = "post",
)]
/// List gateways.
pub async fn list_gateways(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:read"),
    )
    .await?;
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Stamp scopes so the gateways RLS scope-stamp branch
    // (`sentin8_has_scope('sentin8:sys:admin')` - init.sql gateway tiers)
    // mirrors the Rust platform-tier write gate.
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, NULL, $2)")
        .bind(a.env_id())
        .bind(&a.claims.scope)
        .execute(&mut *conn)
        .await;
    // org_id is resolved internally from env_id; not stored on gateways table
    let rows = sqlx::query(
        r#"SELECT id, scope, env_id, channel, provider, config, is_enabled, created_at, updated_at
             FROM gateways
            WHERE (scope = 'sys' AND env_id = $2)
               OR (scope = 'org' AND env_id = $2)
               OR (scope = 'env' AND env_id = $1)
            ORDER BY scope, channel"#,
    )
    .bind(a.env_id())
    .bind(sentin8::config::SYSTEM_ENV_ID)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let gateways: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let scope: String = r.get("scope");
            let channel: String = r.get("channel");
            let provider: String = r.get("provider");
            let config: serde_json::Value = r.get("config");
            let is_enabled: bool = r.get("is_enabled");
            let created_at: chrono::DateTime<chrono::Utc> = r.get("created_at");
            let updated_at: chrono::DateTime<chrono::Utc> = r.get("updated_at");
            serde_json::json!({
                "id": id,
                "scope": scope,
                "channel": channel,
                "provider": provider,
                "config": config,
                "is_enabled": is_enabled,
                "created_at": created_at,
                "updated_at": updated_at,
            })
        })
        .collect();
    Ok(Json(gateways))
}

/// `POST /v1/gateways` - create a gateway config.
/// `POST /v1/gateways` - create a gateway config.
#[utoipa::path(
    post,
    operation_id = "gateway.create",
    path = "/v1/gateways",
    request_body = CreateGatewayRequest,
    responses(
        (status = 200, description = "Gateway created"),
        (status = 403, description = "Missing post:write scope"),
    ),
    security(("sentin8:post:write" = [])),
    tag = "post",
)]
/// Create gateway.
pub async fn create_gateway(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(req): Json<CreateGatewayRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:write"),
    )
    .await?;
    let scope = req.scope.as_str();
    // Sys/org-scope gateways are the platform plane (post design :
    // `post:admin` | platform admins) - a caller without `sentin8:sys:admin`
    // is rejected before any tenant mapping happens.
    if matches!(scope, "sys" | "org") && !a.is_platform_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "system-level gateway configuration requires the platform admin (sentin8:sys:admin) scope".into(),
        ));
    }
    // Resolve target env_id from query param (BFF proxy), fall back to token env_id.
    let target_env = q
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .unwrap_or_else(|| a.env_id());
    let env_id = match scope {
        "sys" => sentin8::config::SYSTEM_ENV_ID,
        "org" => sentin8::config::SYSTEM_ENV_ID,
        "env" => target_env,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "scope must be sys, org, or env".into(),
            ))
        }
    };
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Stamp scopes - the gateways RLS platform-tier branch requires the
    // `sentin8:sys:admin` scope stamp on the writing context (the env
    // alone is the same for sys rows as any tenant's env row).
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, NULL, $2)")
        .bind(env_id)
        .bind(&a.claims.scope)
        .execute(&mut *conn)
        .await;
    let row = sqlx::query(
        r#"INSERT INTO gateways (env_id, scope, channel, provider, config, is_enabled)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(&req.scope)
    .bind(&req.channel)
    .bind(&req.provider)
    .bind(&req.config)
    .bind(req.is_enabled)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let id: Uuid = row.get("id");
    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("commit: {e}")))?;
    tracing::info!(gateway_id = %id, scope = %req.scope, channel = %req.channel, "post: gateway created");
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"id": id, "status": "created"})),
    ))
}

/// `DELETE /v1/gateways/{id}` - delete a gateway config.
/// `DELETE /v1/gateways/{id}` - delete a gateway config.
#[utoipa::path(
    delete,
    operation_id = "gateway.delete",
    path = "/v1/gateways/{id}",
    params(("id" = Uuid, Path, description = "Gateway ID")),
    responses(
        (status = 204, description = "Gateway deleted"),
        (status = 404, description = "Gateway not found"),
        (status = 403, description = "Missing post:write scope"),
    ),
    security(("sentin8:post:write" = [])),
    tag = "post",
)]
/// Delete gateway.
pub async fn delete_gateway(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let _a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:write"),
    )
    .await?;
    // Row-aware delete (principles §4.3d): read the row's env/scope first -
    // the deleting transaction stamps the ROW's env as context (sys/org
    // rows live in the system env, env rows in their own env), matching
    // the gateways RLS tier policy; the explicit predicate remains
    // defense-in-depth. Platform-tier deletes additionally require the
    // caller's `sentin8:sys:admin` scope stamp (RLS mirrors the handler
    // gate).
    let mut conn = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Read-context: the caller's env (+ admin scope when stamped).
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, NULL, $2)")
        .bind(_a.env_id())
        .bind(&_a.claims.scope)
        .execute(&mut *conn)
        .await;
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT env_id, scope FROM gateways WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some((row_env, row_scope)) = row else {
        return Err((StatusCode::NOT_FOUND, "gateway not found".into()));
    };
    if row_scope != "env" && !_a.has_scope("sentin8:sys:admin") {
        return Err((
            StatusCode::FORBIDDEN,
            "platform-tier gateway deletion requires the platform admin (sentin8:sys:admin) scope"
                .into(),
        ));
    }
    // Deleting context: the ROW's env.
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, NULL, $2)")
        .bind(row_env)
        .bind(&_a.claims.scope)
        .execute(&mut *conn)
        .await;
    let result = sqlx::query("DELETE FROM gateways WHERE id = $1 AND env_id = $2")
        .bind(id)
        .bind(row_env)
        .execute(&mut *conn)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    conn.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("commit: {e}")))?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "gateway not found".into()));
    }
    Ok(StatusCode::OK)
}

/// `POST /v1/gateways/test` - send a test message through a gateway.
/// `POST /v1/gateways/test` - test a gateway config.
#[utoipa::path(
    post,
    operation_id = "gateway.test",
    path = "/v1/gateways/test",
    request_body = CreateGatewayRequest,
    responses(
        (status = 200, description = "Gateway test result"),
        (status = 403, description = "Missing post:write scope"),
    ),
    security(("sentin8:post:write" = [])),
    tag = "post",
)]
/// Handle test gateway.
pub async fn test_gateway(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateGatewayRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_cert_or_token(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:post:write"),
    )
    .await?;
    // v1: just log the test and return success.
    tracing::info!(
        scope = %req.scope,
        channel = %req.channel,
        provider = %req.provider,
        "post: gateway test requested (stub - logs only in v1)"
    );
    Ok(Json(serde_json::json!({
        "status": "test_sent",
        "channel": req.channel,
        "provider": req.provider,
        "message": "Test message logged. External delivery will be available when the gateway is configured."
    })))
}

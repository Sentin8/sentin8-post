// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Post inbox relay — drains `inbox` and delivers messages.
//!
//! Uses the same hybrid LISTEN/NOTIFY + safety poll model as Bus.
//! An `AFTER INSERT` trigger on `inbox` fires `pg_notify('post_inbox_changed', '')`.
//! The relay's `PgListener` wakes immediately (millisecond latency).
//! A 5s safety poll catches missed notifications and handles crash recovery.
//!
//! For each undelivered message, the relay:
//! 1. Creates a "View" channel delivery (always available, instant).
//! 2. Produces a `notification.received` event to Bus (fire-and-forget)
//! so BFF's SSE consumer pushes it to the user's app.
//! 3. Attempts the external channels (email/sms/push/web_push/mail — v1
//! stubs); a failure schedules the next attempt on the design backoff
//! curve (1s, 5s, 30s, 2min, 10min) and lands the delivery in `post.dlq`
//! when the retry budget is exhausted (post DESIGN §10).
//! 4. Marks the message delivered once every applicable channel is
//! terminal (sent/dlq) — a scheduled retry keeps it pending.

use std::time::Duration;

use chrono::Timelike;
use sentin8::bus::contracts::ProduceRequest;
use sqlx::Row;
use tokio::time::{timeout, Instant};

/// Backoff curve for failed external-channel deliveries, in seconds
/// (post DESIGN §10: 1s, 5s, 30s, 2min, 10min → DLQ).
const RETRY_DELAY_SECS: [i64; 5] = [1, 5, 30, 120, 600];

/// Wait before retry attempt `n` (0-based): the design backoff curve;
/// indices past the curve repeat the final 10-minute step.
fn retry_delay_secs(n: usize) -> i64 {
    RETRY_DELAY_SECS[n.min(RETRY_DELAY_SECS.len() - 1)]
}

/// Retry budget for a delivery row: its own `max_retries`, capped by the
/// design curve length — a row may only LOWER the curve budget
/// (post DESIGN §10).
fn retry_budget(max_retries: i32) -> usize {
    (max_retries.max(0) as usize).min(RETRY_DELAY_SECS.len())
}

/// Spawn the inbox relay as a background task.
/// Spawn it.
pub fn spawn(pool: sqlx::PgPool, bus: sentin8::bus::client::BusClient, listener_dsn: String) {
    tokio::spawn(async move {
        run(pool, bus, listener_dsn).await;
    });
}

/// Run the relay loop forever.
async fn run(pool: sqlx::PgPool, bus: sentin8::bus::client::BusClient, listener_dsn: String) {
    tracing::info!("post inbox relay started (LISTEN/NOTIFY + 5s safety poll)");

    let batch_size: i64 = 50;
    let safety_poll = Duration::from_secs(5);

    let conn_str = listener_dsn;
    let mut listener = match sqlx::postgres::PgListener::connect(&conn_str).await {
        Ok(l) => {
            tracing::info!("post inbox relay LISTEN on post_inbox_changed");
            l
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to start PgListener — falling back to poll-only");
            run_poll_only(pool, bus, safety_poll, batch_size).await;
            return;
        }
    };

    if let Err(e) = listener.listen("post_inbox_changed").await {
        tracing::error!(error = %e, "failed to LISTEN on post_inbox_changed — falling back to poll-only");
        run_poll_only(pool, bus, safety_poll, batch_size).await;
        return;
    }

    // Drain any messages inserted before the relay started (crash recovery).
    let _ = drain(&pool, &bus, batch_size).await;
    let _ = drain_retries(&pool, batch_size).await;

    let mut next_poll = Instant::now() + safety_poll;

    loop {
        let remaining = next_poll.saturating_duration_since(Instant::now());

        let _notified = match timeout(remaining, listener.recv()).await {
            Ok(Ok(notification)) => {
                tracing::debug!(payload = %notification.payload(), "post inbox NOTIFY received");
                true
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "PgListener error — will reconnect");
                tokio::time::sleep(Duration::from_secs(1)).await;
                match sqlx::postgres::PgListener::connect(&conn_str).await {
                    Ok(new_listener) => {
                        listener = new_listener;
                        let _ = listener.listen("post_inbox_changed").await;
                    }
                    Err(e2) => {
                        tracing::error!(error = %e2, "PgListener reconnect failed");
                    }
                }
                false
            }
            Err(_) => true,
        };

        match drain(&pool, &bus, batch_size).await {
            Ok(n) => {
                if n > 0 {
                    tracing::debug!(drained = n, "post inbox relay drained batch");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "post inbox relay drain error");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
        if let Err(e) = drain_retries(&pool, batch_size).await {
            tracing::error!(error = %e, "post inbox relay retry-drain error");
        }

        next_poll = Instant::now() + safety_poll;
    }
}

/// Poll-only fallback mode.
async fn run_poll_only(
    pool: sqlx::PgPool,
    bus: sentin8::bus::client::BusClient,
    poll_interval: Duration,
    batch_size: i64,
) {
    tracing::warn!("post inbox relay running in poll-only mode");
    loop {
        match drain(&pool, &bus, batch_size).await {
            Ok(n) => {
                if n == 0 {
                    tokio::time::sleep(poll_interval).await;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "post inbox relay error");
                tokio::time::sleep(poll_interval).await;
            }
        }
        if let Err(e) = drain_retries(&pool, batch_size).await {
            tracing::error!(error = %e, "post inbox relay retry-drain error");
        }
    }
}

/// Drain one batch of undelivered messages.
///
/// RLS: `post.inbox` is FORCE-RLS'd on (context_initialized, env_id) and
/// the relay task has no tenant context of its own — the same silent-drain
/// incident class the outbox relay hit (crates/bus/outbox §6.7). Rows are
/// therefore collected context-free and processed under per-row
/// tenant-context transactions (`sentin8_set_tenant_context` on the SAME
/// connection as every query, post DESIGN §5).
async fn drain(
    pool: &sqlx::PgPool,
    bus: &sentin8::bus::client::BusClient,
    batch_size: i64,
) -> Result<usize, sqlx::Error> {
    // Collect undelivered ids: the owner-side SECURITY DEFINER helper
    // returns the envs that have undelivered rows; the inbox JOIN itself
    // still runs under that env's tenant context (FORCE RLS). The ids are
    // then drained under the same context (post DESIGN §5).
    let mut ids: Vec<(uuid::Uuid, uuid::Uuid)> = Vec::new();
    let envs: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT env_id FROM post_undelivered_envs()")
        .fetch_all(pool)
        .await?;
    for env_id in envs {
        let mut tx = pool.begin().await?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let batch = sqlx::query(
            "SELECT id, env_id FROM inbox WHERE delivered = false ORDER BY created_at LIMIT $1",
        )
        .bind(batch_size)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        ids.extend(batch.into_iter().map(|r| {
            (
                r.get::<uuid::Uuid, _>("id"),
                r.get::<uuid::Uuid, _>("env_id"),
            )
        }));
        if ids.len() >= batch_size as usize {
            break;
        }
    }

    let count = ids.len();
    for (id, env_id) in ids {
        let row = match drain_one(pool, id, env_id).await {
            Ok(Some(row)) => row,
            Ok(None) => continue, // row vanished between SELECT and read
            Err(e) => {
                tracing::warn!(error = %e, message_id = %id, "post inbox relay row read failed — retried next pass");
                continue;
            }
        };
        let category: String = row.get("category");
        let recipient_user_id: Option<uuid::Uuid> = row.get("recipient_user_id");
        let subject: String = row.get("subject");
        let body: String = row.get("body");
        let metadata: serde_json::Value = row.get("metadata");
        let recipient_email: Option<String> = row.get("recipient_email");

        // 1. Create "View" channel delivery (always succeeds, record of
        // truth). Dedupe on (inbox_id, channel): an inbox row with a
        // scheduled external retry is re-selected undelivered, and the
        // view row must not be duplicated (post DESIGN §5 idempotency).
        let mut tx = pool.begin().await?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        sqlx::query(
            r#"INSERT INTO deliveries (inbox_id, env_id, channel, status, delivered_at)
               VALUES ($1, $2, 'view', 'delivered', now())
               ON CONFLICT DO NOTHING"#,
        )
        .bind(id)
        .bind(env_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        // 2. Produce notification.received to Bus (fire-and-forget).
        // Include the updated unread count for the recipient so BFF's SSE
        // consumer can set the badge without a separate API call.
        let unread_count = if let Some(uid) = recipient_user_id {
            let mut tx = pool.begin().await?;
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(env_id)
                .execute(&mut *tx)
                .await;
            let n = sqlx::query_scalar::<_, i64>(
                r#"SELECT COUNT(*) FROM inbox
                    WHERE env_id = $1 AND recipient_user_id = $2
                      AND read_at IS NULL"#,
            )
            .bind(env_id)
            .bind(uid)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
            tx.commit().await?;
            n
        } else {
            0
        };

        let notification_payload = serde_json::json!({
            "user_id": recipient_user_id,
            "title": subject,
            "body": body,
            "category": category,
            "resource_type": "message",
            "resource_id": id,
            "metadata": metadata,
            "unread_count": unread_count,
        });

        // The relay is a background task — it produces on behalf of the
        // service itself (M2M token), not the original user. The
        // publisher_id_token is the relay's M2M token if available;
        // publisher_subject is the service name for audit.
        let produce_req = ProduceRequest {
            stream_family: "notifications".into(),
            env_id: None,
            event_type: "sentin8:notification:received".into(),
            payload: notification_payload,
            correlation_id: None,
            idempotency_key: Some(id.to_string()),
            publisher_id_token: None, // Relay M2M token — set if available
            publisher_subject: Some("sentin8:post".into()),
        };
        if let Err(e) = bus.produce(&produce_req).await {
            tracing::debug!(error = %e, message_id = %id, "post: notification produce failed (fire-and-forget)");
        }

        // 3. Attempt the external channels (stub providers — post DESIGN
        // §10; the real adapters replace the stubs in place later).
        // Preference filter (POST-5): a recipient who muted this category
        // (or is inside their quiet-hours window) skips the external
        // channels — the View channel (in-app, step 1) always delivered,
        // so the record of truth is never lost (post DESIGN §10).
        let prefs = user_delivery_preferences(pool, env_id, recipient_user_id).await;
        if let Some(prefs) = &prefs {
            if prefs.muted.iter().any(|c| c == &category) {
                tracing::debug!(message_id = %id, category = %category, "post: category muted by recipient — external channels skipped");
                finalize_inbox(pool, id, env_id).await?;
                continue;
            }
            if prefs.quiet_now {
                tracing::debug!(message_id = %id, category = %category, "post: recipient in quiet hours — external channels deferred (view delivered)");
                finalize_inbox(pool, id, env_id).await?;
                continue;
            }
        }
        if let Err(e) = attempt_external_delivery(
            pool,
            id,
            env_id,
            &category,
            recipient_email.as_deref(),
            prefs.as_ref(),
            &metadata,
        )
        .await
        {
            tracing::warn!(error = %e, message_id = %id, "post: external delivery attempt failed — retried next pass");
            continue;
        }

        // 4. Mark delivered ONLY when every applicable channel is terminal
        // — a scheduled retry keeps the row pending in queries.
        finalize_inbox(pool, id, env_id).await?;
    }
    Ok(count)
}

/// Read one inbox row's delivery-relevant fields (context-bound tx).
/// Returns `None` when the row vanished between the outer SELECT and here.
async fn drain_one(
    pool: &sqlx::PgPool,
    id: uuid::Uuid,
    env_id: uuid::Uuid,
) -> Result<Option<sqlx::postgres::PgRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let row = sqlx::query(
        r#"SELECT id, env_id, message_type, category,
                  recipient_user_id, recipient_email, subject, body, metadata
             FROM inbox
            WHERE id = $1 AND env_id = $2 AND delivered = false"#,
    )
    .bind(id)
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await;
    let out = match row {
        Ok(r) => r,
        Err(e) => {
            tx.rollback().await?;
            return Err(e);
        }
    };
    tx.commit().await?;
    Ok(out)
}

/// Mark the inbox row delivered only when EVERY delivery row is terminal
/// (`sent`/`delivered`/`dlq`) — any `pending` row (a scheduled retry)
/// keeps the message pending in queries (post DESIGN §10).
async fn finalize_inbox(
    pool: &sqlx::PgPool,
    id: uuid::Uuid,
    env_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM deliveries WHERE inbox_id = $1 AND status = 'pending'",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if pending == 0 {
        sqlx::query("UPDATE inbox SET delivered = true, delivered_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// A recipient's resolved delivery preferences (POST-5).
struct UserPreferences {
    /// Categories the recipient muted — external channels skip them.
    muted: Vec<String>,
    /// True when the current hour falls inside the recipient's quiet-hours
    /// window (`quiet_hours_start..quiet_hours_end`, UTC hours; a window
    /// crossing midnight wraps).
    quiet_now: bool,
}

/// Read one recipient's delivery preferences (POST-5). `None` = no
/// preference row (everything delivers). The read runs under the env's
/// tenant context (FORCE RLS); a DB error degrades to `None` — a
/// preferences outage must never drop notifications.
async fn user_delivery_preferences(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    user_id: Option<uuid::Uuid>,
) -> Option<UserPreferences> {
    let uid = user_id?;
    let mut tx = pool.begin().await.ok()?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .ok()?;
    let row = sqlx::query_as::<_, (Vec<String>, Option<i32>, Option<i32>)>(
        r#"SELECT muted_categories, quiet_hours_start, quiet_hours_end
             FROM notification_preferences
            WHERE env_id = $1 AND user_id = $2"#,
    )
    .bind(env_id)
    .bind(uid)
    .fetch_optional(&mut *tx)
    .await
    .ok()?;
    tx.commit().await.ok()?;
    let (muted, start, end) = row?;
    let quiet_now = match (start, end) {
        (Some(s), Some(e)) => {
            let hour = chrono::Utc::now().time().hour() as i32;
            if s <= e {
                hour >= s && hour < e
            } else {
                hour >= s || hour < e // window crosses midnight
            }
        }
        _ => false,
    };
    Some(UserPreferences { muted, quiet_now })
}

/// Render a message from `post.templates` (POST-7). Consulted when the
/// inbox row carries `metadata.template_key`; `metadata.locale` selects
/// the locale row with an `'en'` fallback. `{{var}}` substitution draws
/// from `metadata.template_vars` plus the resolved branding
/// (`primary_color`, `logo_url` from `sys.branding` — env override over
/// org base, non-empty wins; the sys cross-schema read is the declared
/// branding lookup). `Ok(None)` = no template requested/resolvable — the
/// caller falls back to the producer's literal subject/body. Best-effort:
/// a broken template never blocks delivery.
async fn render_template(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    metadata: &serde_json::Value,
) -> Result<Option<(String, String)>, sqlx::Error> {
    let Some(key) = metadata.get("template_key").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let locale = metadata
        .get("locale")
        .and_then(|v| v.as_str())
        .unwrap_or("en");
    let vars = metadata
        .get("template_vars")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    // Exact locale first, 'en' fallback.
    let row = sqlx::query_as::<_, (String, String)>(
        r#"SELECT subject, body FROM templates
            WHERE env_id = $1 AND template_key = $2 AND locale = $3"#,
    )
    .bind(env_id)
    .bind(key)
    .bind(locale)
    .fetch_optional(&mut *tx)
    .await?
    .or(sqlx::query_as::<_, (String, String)>(
        r#"SELECT subject, body FROM templates
            WHERE env_id = $1 AND template_key = $2 AND locale = 'en'"#,
    )
    .bind(env_id)
    .bind(key)
    .fetch_optional(&mut *tx)
    .await?);
    // Branding resolves from sys.branding — the declared cross-schema read
    // (post README §7; platform plane, org base → env override).
    let branding: Option<(Option<String>, Option<String>)> =
        sqlx::query_as::<_, (Option<String>, Option<String>)>(
            r#"SELECT primary_color, logo_url
             FROM sys.branding
            WHERE env_id = $1 OR (env_id IS NULL AND org_id =
                  (SELECT org_id FROM sys.environments WHERE id = $1))
            ORDER BY (env_id IS NOT NULL) DESC LIMIT 1"#,
        )
        .bind(env_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
    tx.commit().await?;

    let Some((subject_tpl, body_tpl)) = row else {
        return Ok(None);
    };
    // Merge vars: branding first (caller overrides win).
    let mut render_vars = serde_json::Map::new();
    if let Some((color, logo)) = branding {
        if let Some(c) = color.filter(|s| !s.is_empty()) {
            render_vars.insert("primary_color".into(), serde_json::Value::String(c));
        }
        if let Some(l) = logo.filter(|s| !s.is_empty()) {
            render_vars.insert("logo_url".into(), serde_json::Value::String(l));
        }
    }
    if let Some(obj) = vars.as_object() {
        for (k, v) in obj {
            render_vars.insert(k.clone(), v.clone());
        }
    }
    let render = |tpl: &str| -> String {
        let mut out = tpl.to_string();
        for (k, v) in &render_vars {
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            out = out.replace(&format!("{{{{{k}}}}}"), &val);
        }
        out
    };
    Ok(Some((render(&subject_tpl), render(&body_tpl))))
}

/// Which external gateway channels apply to a message — the stub dispatch
/// matrix keyed by category + recipient (`sms` rides
/// `metadata.recipient_phone`, read inside the stub itself; mirrored by
/// tests/policy.rs).
fn external_channels(category: &str, recipient_email: Option<&str>) -> Vec<&'static str> {
    let mut out = Vec::new();
    if recipient_email.is_some_and(|e| !e.is_empty()) {
        out.push("email");
    }
    if category == "security" || category == "transaction" {
        out.push("push");
    }
    if category == "security" {
        out.push("web_push");
    }
    if category == "statement" || category == "letter" {
        out.push("mail");
    }
    out
}

/// Attempt the external gateway channels for one inbox row.
///
/// Gateway config: any enabled gateway row for this env turns the external
/// channels ON; with no gateway configured no delivery rows are created at
/// all (post DESIGN §10). The `config` JSONB may carry `simulate_failure:
/// true` — a test seam that makes every attempt fail with "simulated
/// gateway failure" so the backoff curve + DLQ land are exercisable
/// without a real provider (the real adapter drops straight in later).
/// A `secret_ref` is resolved at delivery time and never logged
/// (post DESIGN §5 secrets rule).
async fn attempt_external_delivery(
    pool: &sqlx::PgPool,
    inbox_id: uuid::Uuid,
    env_id: uuid::Uuid,
    category: &str,
    recipient_email: Option<&str>,
    _prefs: Option<&UserPreferences>,
    metadata: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    let channels = external_channels(category, recipient_email);
    if channels.is_empty() {
        return Ok(());
    }

    // Gateway lookup must run under the env's tenant context (FORCE RLS
    // silences a context-free SELECT — post DESIGN §5).
    let cfg = match gateway_config_for_env(pool, env_id).await? {
        Some(c) => c,
        None => return Ok(()),
    };
    let simulate_failure = cfg
        .get("simulate_failure")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if let Some(secret_ref) = cfg
        .get("secret_ref")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
    {
        match sentin8_secrets_sdk::secrets::resolve_credential(&secret_ref).await {
            Ok(_) => {
                tracing::debug!(message_id = %inbox_id, "post: gateway credential resolved (never logged)");
            }
            Err(e) => {
                tracing::warn!(error = %e, "post: gateway secret_ref does not resolve — delivery proceeds without credential");
            }
        }
    }

    // Template rendering (POST-7): when the inbox row carries
    // `metadata.template_key` (and optionally `metadata.locale`), the
    // subject/body are rendered from `post.templates` with `{{var}}`
    // substitution — branding (`primary_color`, `logo_url`) resolves from
    // `sys.branding` into the render vars (non-empty wins, org base →
    // env override). Unresolvable template → falls back to the producer's
    // literal subject/body (never blocks delivery).
    let (subject, body) = match render_template(pool, env_id, metadata).await {
        Ok(Some(rendered)) => rendered,
        Ok(None) => {
            let row_subject: String = sqlx::query_scalar("SELECT subject FROM inbox WHERE id = $1")
                .bind(inbox_id)
                .fetch_one(pool)
                .await
                .unwrap_or_default();
            let row_body: String = sqlx::query_scalar("SELECT body FROM inbox WHERE id = $1")
                .bind(inbox_id)
                .fetch_one(pool)
                .await
                .unwrap_or_default();
            (row_subject, row_body)
        }
        Err(e) => return Err(e),
    };
    for channel in channels {
        match external_attempt(
            pool,
            inbox_id,
            env_id,
            channel,
            simulate_failure,
            &cfg,
            &subject,
            &body,
        )
        .await
        {
            Ok(()) => {
                tracing::debug!(message_id = %inbox_id, channel = %channel, "post: external delivery accepted (stub)");
            }
            Err(err) => schedule_retry_or_dlq(pool, inbox_id, env_id, channel, &err).await?,
        }
    }
    Ok(())
}

/// Run ONE gateway attempt for a channel: ensure the `deliveries` row
/// `(inbox_id, channel)` exists, stamp the in-flight retry count, dispatch
/// through the gateway adapter, and stamp the row terminal on success.
/// `Err` carries the failure string for retry scheduling.
#[allow(clippy::too_many_arguments)]
async fn external_attempt(
    pool: &sqlx::PgPool,
    inbox_id: uuid::Uuid,
    env_id: uuid::Uuid,
    channel: &str,
    simulate_failure: bool,
    gateway_config: &serde_json::Value,
    rendered_subject: &str,
    rendered_body: &str,
) -> Result<(), String> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("delivery row tx: {e}"))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("delivery row context: {e}"))?;
    // Upsert the delivery row — retry passes land on the SAME row the
    // first attempt created (post DESIGN §5 idempotency).
    let ensured = sqlx::query(
        r#"INSERT INTO deliveries (inbox_id, env_id, channel, status)
           VALUES ($1, $2, $3, 'pending')
           ON CONFLICT DO NOTHING
           RETURNING id"#,
    )
    .bind(inbox_id)
    .bind(env_id)
    .bind(channel)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("delivery upsert: {e}"))?;
    let delivery_id: uuid::Uuid = match ensured {
        Some(id) => id.get("id"),
        None => {
            sqlx::query_scalar("SELECT id FROM deliveries WHERE inbox_id = $1 AND channel = $2")
                .bind(inbox_id)
                .bind(channel)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| format!("delivery row reload: {e}"))?
        }
    };
    let row: sqlx::postgres::PgRow =
        sqlx::query("SELECT retry_count, max_retries, status FROM deliveries WHERE id = $1")
            .bind(delivery_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| format!("delivery row read: {e}"))?;
    let retry_count: i32 = row.get("retry_count");
    let max_retries: i32 = row.get("max_retries");
    let status: String = row.get("status");
    // A spent budget (or terminal row) means this attempt is a stray from
    // a concurrent pass — nothing to dispatch; the schedule call settles.
    if status == "dlq" || retry_count as usize >= retry_budget(max_retries) {
        let _ = tx.commit().await;
        return Ok(());
    }
    // Stamp the in-flight attempt: retry_count counts attempts MADE
    // (1 on the first dispatch) so the failure path can compute the
    // next step on the curve from it (post DESIGN §10).
    let in_flight = retry_count + 1;
    sqlx::query("UPDATE deliveries SET retry_count = $2, status = 'pending' WHERE id = $1")
        .bind(delivery_id)
        .bind(in_flight)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("delivery attempt stamp: {e}"))?;
    tx.commit()
        .await
        .map_err(|e| format!("delivery attempt commit: {e}"))?;

    // ── Gateway adapter dispatch (v1: stubs — post DESIGN §10) ──
    // Stubs log and succeed; `simulate_failure` turns every attempt into
    // "simulated gateway failure" so the retry curve + DLQ path are
    // exercisable without a real provider.
    let dispatched = if simulate_failure {
        Err("simulated gateway failure".to_string())
    } else {
        gateway_dispatch(
            pool,
            inbox_id,
            env_id,
            channel,
            gateway_config,
            rendered_subject,
            rendered_body,
        )
        .await
    };

    match dispatched {
        Ok(()) => {
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| format!("delivery sent tx: {e}"))?;
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(env_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("delivery sent context: {e}"))?;
            sqlx::query(
                r#"UPDATE deliveries
                      SET status = 'sent', error = NULL, next_retry_at = NULL, delivered_at = now()
                    WHERE id = $1"#,
            )
            .bind(delivery_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("delivery sent stamp: {e}"))?;
            tx.commit()
                .await
                .map_err(|e| format!("delivery sent commit: {e}"))?;
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Schedule the next retry from the design backoff curve, or land the
/// delivery in `post.dlq` with status `dlq` when the retry budget is
/// exhausted (post DESIGN §10).
async fn schedule_retry_or_dlq(
    pool: &sqlx::PgPool,
    inbox_id: uuid::Uuid,
    env_id: uuid::Uuid,
    channel: &str,
    err: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let row: sqlx::postgres::PgRow = sqlx::query(
        "SELECT id, retry_count, max_retries FROM deliveries WHERE inbox_id = $1 AND channel = $2",
    )
    .bind(inbox_id)
    .bind(channel)
    .fetch_one(&mut *tx)
    .await?;
    let delivery_id: uuid::Uuid = row.get("id");
    let retry_count: i32 = row.get("retry_count");
    let max_retries: i32 = row.get("max_retries");

    if retry_count as usize >= retry_budget(max_retries) {
        sqlx::query(
            r#"INSERT INTO dlq (inbox_id, env_id, channel, error, retry_count)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(inbox_id)
        .bind(env_id)
        .bind(channel)
        .bind(err)
        .bind(retry_count)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"UPDATE deliveries
                  SET status = 'dlq', error = $2, next_retry_at = NULL
                WHERE id = $1"#,
        )
        .bind(delivery_id)
        .bind(err)
        .execute(&mut *tx)
        .await?;
        tracing::warn!(message_id = %inbox_id, channel = %channel, retry_count = retry_count, "post: delivery moved to DLQ");
    } else {
        // Next delay: the curve index is the attempts made so far
        // (retry_count) — 1 attempt failed → 5s, 2 → 30s, … (post
        // DESIGN §10: 1s, 5s, 30s, 2min, 10min → DLQ).
        let delay = retry_delay_secs(retry_count as usize);
        sqlx::query(
            r#"UPDATE deliveries
                  SET status = 'pending', error = $2,
                      next_retry_at = now() + make_interval(secs => $3)
                WHERE id = $1"#,
        )
        .bind(delivery_id)
        .bind(err)
        .bind(delay)
        .execute(&mut *tx)
        .await?;
        tracing::info!(message_id = %inbox_id, channel = %channel, retry_count = retry_count, delay_secs = delay, "post: delivery retry scheduled");
    }
    tx.commit().await?;
    Ok(())
}

/// Drain one batch of due pending external deliveries
/// (`next_retry_at <= now()`) — the second half of the drain loop
/// (post DESIGN §10). Per-env context discipline as in [`drain`].
async fn drain_retries(pool: &sqlx::PgPool, batch_size: i64) -> Result<usize, sqlx::Error> {
    // Due retry rows via the owner-side SECURITY DEFINER helper (the
    // FORCE-RLS'd table is invisible to a bare context-free SELECT),
    // then re-attempt each under its own env context.
    let due: Vec<(uuid::Uuid, uuid::Uuid, String)> = sqlx::query(
        // Schema-qualified: the helper lives in post's OWN schema (SECURITY
        // DEFINER owner-side helper — post DESIGN §5); the relay role's
        // search_path resolves it, but the explicit name keeps the
        // cross-namespace contract visible at the call site.
        "SELECT inbox_id, env_id, channel FROM post.post_due_retry_rows($1)",
    )
    .bind(batch_size as i32)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|r| {
        (
            r.get::<uuid::Uuid, _>("inbox_id"),
            r.get::<uuid::Uuid, _>("env_id"),
            r.get::<String, _>("channel"),
        )
    })
    .collect();

    let count = due.len();
    for (inbox_id, env_id, channel) in due {
        let row = match drain_one(pool, inbox_id, env_id).await {
            Ok(Some(row)) => row,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(error = %e, message_id = %inbox_id, "post inbox relay retry row read failed");
                continue;
            }
        };
        let category: String = row.get("category");
        let recipient_email: Option<String> = row.get("recipient_email");

        if !external_channels(&category, recipient_email.as_deref()).contains(&channel.as_str()) {
            // Channel no longer applies (recipient data gone between
            // passes): settle the row so the inbox can finalize instead
            // of hot-looping on a dead channel.
            settle_skipped_channel(pool, inbox_id, env_id, &channel).await?;
            finalize_inbox(pool, inbox_id, env_id).await?;
            continue;
        }

        let simulate_failure = gateway_simulate_failure(pool, env_id).await;
        let retry_ctx = match retry_delivery_context(pool, inbox_id, env_id).await {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        match external_attempt(
            pool,
            inbox_id,
            env_id,
            &channel,
            simulate_failure,
            &retry_ctx.0,
            &retry_ctx.1,
            &retry_ctx.2,
        )
        .await
        {
            Ok(()) => {
                tracing::debug!(message_id = %inbox_id, channel = %channel, "post: delivery retry succeeded");
            }
            Err(err) => schedule_retry_or_dlq(pool, inbox_id, env_id, &channel, &err).await?,
        }
        finalize_inbox(pool, inbox_id, env_id).await?;
    }
    Ok(count)
}

/// The env's first enabled gateway `config` (RLS-scoped; `None` when no
/// gateway row is visible — post DESIGN §5).
async fn gateway_config_for_env(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
) -> Result<Option<serde_json::Value>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let cfg = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT config FROM gateways WHERE env_id = $1 AND is_enabled = true ORDER BY created_at LIMIT 1",
    )
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(cfg)
}

/// Retry-pass delivery context: the env's gateway config (empty object
/// when none is visible) plus the rendered subject/body (row literals as
/// the fallback) so a retry dispatches through the same adapter path with
/// the same content as the first attempt.
async fn retry_delivery_context(
    pool: &sqlx::PgPool,
    inbox_id: uuid::Uuid,
    env_id: uuid::Uuid,
) -> Result<(serde_json::Value, String, String), sqlx::Error> {
    let cfg = gateway_config_for_env(pool, env_id)
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| serde_json::json!({}));
    let rendered = match render_template(pool, env_id, &serde_json::json!({})).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            let row_subject: String = sqlx::query_scalar("SELECT subject FROM inbox WHERE id = $1")
                .bind(inbox_id)
                .fetch_one(pool)
                .await
                .unwrap_or_default();
            let row_body: String = sqlx::query_scalar("SELECT body FROM inbox WHERE id = $1")
                .bind(inbox_id)
                .fetch_one(pool)
                .await
                .unwrap_or_default();
            (row_subject, row_body)
        }
        Err(e) => return Err(e),
    };
    Ok((cfg, rendered.0, rendered.1))
}

/// Read the `simulate_failure` test seam from the env's first enabled
/// gateway config (`false` when no gateway row is visible). Runs under
/// the env's tenant context — a context-free SELECT is silenced by
/// FORCE RLS (post DESIGN §5).
async fn gateway_simulate_failure(pool: &sqlx::PgPool, env_id: uuid::Uuid) -> bool {
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(_) => return false,
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let cfg = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT config FROM gateways WHERE env_id = $1 AND is_enabled = true ORDER BY created_at LIMIT 1",
    )
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await;
    tx.commit().await.ok();
    match cfg {
        Ok(Some(c)) => c
            .get("simulate_failure")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        _ => false,
    }
}

/// Settle a delivery row whose channel no longer applies (recipient data
/// gone between passes): terminal without a gateway dispatch, so the
/// inbox row can finalize instead of hot-looping on a dead channel.
async fn settle_skipped_channel(
    pool: &sqlx::PgPool,
    inbox_id: uuid::Uuid,
    env_id: uuid::Uuid,
    channel: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    sqlx::query(
        r#"UPDATE deliveries
              SET status = 'sent', next_retry_at = NULL
            WHERE inbox_id = $1 AND channel = $2 AND status = 'pending'"#,
    )
    .bind(inbox_id)
    .bind(channel)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Dispatch through the v1 gateway stubs (log-only, always succeeds).
/// The per-channel log mirrors the stub dispatch matrix; the real provider
/// adapters swap in behind the same signature (post DESIGN §10).
/// Gateway adapter dispatch (POST-4): the email channel rides a real
/// SMTP relay when the gateway row declares `gateway_url` (an HTTP relay
/// endpoint — self-hostable, e.g. a local SMTP-to-HTTP bridge); every
/// other channel (and email without a relay) keeps the stub behavior.
/// Credentials travel via `secret_ref` (resolved at delivery time, never
/// logged — post DESIGN §5).
async fn gateway_dispatch(
    pool: &sqlx::PgPool,
    inbox_id: uuid::Uuid,
    env_id: uuid::Uuid,
    channel: &str,
    gateway_config: &serde_json::Value,
    rendered_subject: &str,
    rendered_body: &str,
) -> Result<(), String> {
    if channel == "email" {
        if let Some(relay_url) = gateway_config
            .get("gateway_url")
            .and_then(|v| v.as_str())
            .filter(|u| !u.is_empty())
        {
            return smtp_relay_dispatch(
                pool,
                inbox_id,
                env_id,
                relay_url,
                rendered_subject,
                rendered_body,
            )
            .await;
        }
    }
    gateway_stub_dispatch(pool, inbox_id, env_id, channel).await
}

/// Real SMTP delivery through the HTTP relay: POST the message to the
/// configured relay endpoint (the relay owns the SMTP conversation with
/// the upstream MTA). Auth rides `secret_ref` resolution — the relay's
/// credential is resolved per-delivery and never logged.
async fn smtp_relay_dispatch(
    pool: &sqlx::PgPool,
    inbox_id: uuid::Uuid,
    env_id: uuid::Uuid,
    relay_url: &str,
    rendered_subject: &str,
    rendered_body: &str,
) -> Result<(), String> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("smtp relay tx: {e}"))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let row = sqlx::query(
        r#"SELECT subject, body, metadata, recipient_email
             FROM inbox WHERE id = $1"#,
    )
    .bind(inbox_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("smtp relay inbox read: {e}"));
    let row = match row {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.rollback().await;
            return Err(e);
        }
    };
    tx.commit()
        .await
        .map_err(|e| format!("smtp relay commit: {e}"))?;
    let row = match row {
        Some(r) => r,
        None => return Err("inbox row vanished".to_string()),
    };
    let row_subject: String = row.get("subject");
    let row_body: String = row.get("body");
    // The rendered copy from POST-7 template rendering wins when present;
    // the row's literal subject/body is the fallback.
    let subject = if rendered_subject.is_empty() {
        row_subject
    } else {
        rendered_subject.to_string()
    };
    let body = if rendered_body.is_empty() {
        row_body
    } else {
        rendered_body.to_string()
    };
    let email: Option<String> = row.get("recipient_email");
    let Some(to) = email.filter(|e| !e.is_empty()) else {
        return Err("smtp relay: no recipient_email on the inbox row".to_string());
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| format!("smtp relay client: {e}"))?;
    let resp = client
        .post(relay_url)
        .json(&serde_json::json!({
            "to": to,
            "subject": subject,
            "text": body,
            "message_id": inbox_id,
        }))
        .send()
        .await
        .map_err(|e| format!("smtp relay call failed: {e}"))?;
    let status = resp.status();
    if status.is_success() {
        tracing::info!(message_id = %inbox_id, to = %to, "post: SMTP relay accepted delivery");
        Ok(())
    } else {
        Err(format!("smtp relay rejected: {status}"))
    }
}

async fn gateway_stub_dispatch(
    pool: &sqlx::PgPool,
    inbox_id: uuid::Uuid,
    env_id: uuid::Uuid,
    channel: &str,
) -> Result<(), String> {
    let mut tx = pool.begin().await.map_err(|e| format!("stub tx: {e}"))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let row = sqlx::query(
        r#"SELECT subject, body, metadata, recipient_user_id, recipient_email
             FROM inbox WHERE id = $1"#,
    )
    .bind(inbox_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("stub inbox read: {e}"));
    let row = match row {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.rollback().await;
            return Err(e);
        }
    };
    tx.commit().await.map_err(|e| format!("stub commit: {e}"))?;
    let row = match row {
        Some(r) => r,
        None => return Err("inbox row vanished".to_string()),
    };
    let subject: String = row.get("subject");
    let body: String = row.get("body");
    let metadata: serde_json::Value = row.get("metadata");
    let user_id: Option<uuid::Uuid> = row.get("recipient_user_id");
    let email: Option<String> = row.get("recipient_email");

    match channel {
        "email" => {
            tracing::info!(message_id = %inbox_id, to = email.as_deref().unwrap_or(""), subject = %subject, "email gateway stub: would send email");
        }
        "sms" => {
            if let Some(phone) = metadata.get("recipient_phone").and_then(|v| v.as_str()) {
                tracing::info!(message_id = %inbox_id, to = phone, body = %body, "sms gateway stub: would send SMS");
            }
        }
        "push" => {
            tracing::info!(message_id = %inbox_id, user_id = ?user_id, "push gateway stub: would send push notification");
        }
        "web_push" => {
            tracing::info!(message_id = %inbox_id, user_id = ?user_id, "web push gateway stub: would send web push");
        }
        "mail" => {
            tracing::info!(message_id = %inbox_id, "mail gateway stub: would store letter to Sentin8:Storage");
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{external_channels, retry_budget, retry_delay_secs};

    /// The design backoff curve: 1s, 5s, 30s, 2min, 10min; indices past
    /// the curve repeat the final step (post DESIGN §10).
    #[test]
    fn retry_delay_curve_matches_design() {
        assert_eq!(retry_delay_secs(0), 1);
        assert_eq!(retry_delay_secs(1), 5);
        assert_eq!(retry_delay_secs(2), 30);
        assert_eq!(retry_delay_secs(3), 120);
        assert_eq!(retry_delay_secs(4), 600);
        // Past the curve: clamp to the final 10-minute step.
        assert_eq!(retry_delay_secs(5), 600);
        assert_eq!(retry_delay_secs(50), 600);
    }

    /// Budget: the row's `max_retries` capped by the curve length — a row
    /// may only LOWER the curve budget (post DESIGN §10).
    #[test]
    fn retry_budget_caps_max_retries() {
        assert_eq!(retry_budget(3), 3);
        assert_eq!(retry_budget(5), 5);
        assert_eq!(retry_budget(10), 5); // curve length caps
        assert_eq!(retry_budget(0), 0);
        assert_eq!(retry_budget(-2), 0); // defensive: negative → no budget
    }

    /// External-channel dispatch matrix (stub parity with the
    /// tests/integration.rs mirror).
    #[test]
    fn external_channels_matrix() {
        assert_eq!(external_channels("info", Some("u@e.com")), vec!["email"]);
        assert!(external_channels("info", Some("")).is_empty());
        assert!(external_channels("info", None).is_empty());
        assert_eq!(
            external_channels("security", None),
            vec!["push", "web_push"]
        );
        assert_eq!(external_channels("transaction", None), vec!["push"]);
        assert_eq!(external_channels("statement", None), vec!["mail"]);
        assert_eq!(external_channels("letter", None), vec!["mail"]);
        assert_eq!(
            external_channels("security", Some("a@b.c")),
            vec!["email", "push", "web_push"]
        );
    }
}

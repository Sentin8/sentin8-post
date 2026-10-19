// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Post Admin UI handlers - RFW definitions.
//! Served from `GET /v1/admin/ui/{page}`, rendered by Sentin8:Dash at runtime.

use crate::handlers::AppState;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use serde::Deserialize;
use sqlx::Row;

#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The targetenvquery type.
pub struct TargetEnvQuery {
    #[serde(default)]
    /// target env identifier.
    pub target_env_id: Option<String>,
}

/// Fetch admin ui.
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    params(
        ("page" = String, Path, description = "RFW page name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "RFW page definition (rendered by Sentin8:Dash)", body = serde_json::Value),
        (status = 403, description = "Caller lacks a post read/admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    security(("sentin8:post:read" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<TargetEnvQuery>,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a = crate::auth::require_any_scope(
        &state.config,
        &headers,
        &[
            "sentin8:post:read",
            "sentin8:post:write",
            "sentin8:sys:admin",
            "sentin8:sys:org:admin",
            "sentin8:sys:env:admin",
        ],
    )
    .await?;
    let def = match page.as_str() {
        "overview" => AdminPage::new("Post Overview")
            .widget(card(
                "Summary",
                "Messages sent, gateways configured, DLQ depth.",
            ))
            .build(),
        "messages" => AdminPage::new("Messages")
            .widget(table_with_actions(
                vec![
                    col("id", "Message ID"),
                    cols("to", "To"),
                    cols("subject", "Subject"),
                    cols("status", "Status"),
                ],
                "/messages",
                vec![row_action_post("Replay", "messages/{id}/replay")],
            ))
            .build(),
        "gateways" => AdminPage::new("Gateways")
            .action(link("Create Gateway", "gateways/new"))
            .widget(table_with_actions(
                vec![
                    col("id", "Gateway ID"),
                    cols("name", "Name"),
                    cols("type", "Type"),
                    cols("status", "Status"),
                ],
                "/gateways",
                vec![row_action_post("Delete", "gateways/{id}/delete")],
            ))
            .build(),
        "gateways/new" => AdminPage::new("Create Gateway")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "scope".into(),
                        label: "Scope".into(),
                        field_type: FormFieldType::Select,
                        required: true,
                        placeholder: None,
                        // Tenant-scoped by default - the 'sys'/'org' scopes
                        // are the platform plane and REQUIRE the platform
                        // admin scope (post DESIGN §5); a default of 'sys'
                        // made every operator-created gateway fail the
                        // FORCE-RLS WITH CHECK (500) unless the caller held
                        // sys:admin.
                        default_value: Some(serde_json::json!("env")),
                        options: Some(vec![
                            FormFieldOption {
                                value: "sys".into(),
                                label: "System".into(),
                            },
                            FormFieldOption {
                                value: "org".into(),
                                label: "Organization".into(),
                            },
                            FormFieldOption {
                                value: "env".into(),
                                label: "Environment".into(),
                            },
                        ]),
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "channel".into(),
                        label: "Channel".into(),
                        field_type: FormFieldType::Select,
                        required: true,
                        placeholder: None,
                        default_value: Some(serde_json::json!("email")),
                        options: Some(vec![
                            FormFieldOption {
                                value: "email".into(),
                                label: "Email".into(),
                            },
                            FormFieldOption {
                                value: "sms".into(),
                                label: "SMS".into(),
                            },
                            FormFieldOption {
                                value: "push".into(),
                                label: "Push".into(),
                            },
                        ]),
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "provider".into(),
                        label: "Provider".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. smtp".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "config".into(),
                        label: "Config (JSON)".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: Some("{\"host\":\"...\",\"port\":25}".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some("Provider-specific config as JSON.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "is_enabled".into(),
                        label: "Enabled".into(),
                        field_type: FormFieldType::Select,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!(true)),
                        options: Some(vec![
                            FormFieldOption {
                                value: "true".into(),
                                label: "Yes".into(),
                            },
                            FormFieldOption {
                                value: "false".into(),
                                label: "No".into(),
                            },
                        ]),
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/gateways".into(),
                submit_label: "Create Gateway".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "dlq" => AdminPage::new("DLQ")
            .widget(table(
                vec![
                    col("id", "DLQ ID"),
                    cols("inbox_id", "Inbox ID"),
                    cols("channel", "Channel"),
                    cols("error", "Error"),
                ],
                "/dlq",
            ))
            .build(),
        "preferences" => AdminPage::new("Notification Preferences")
            .widget(table(
                vec![
                    col("id", "Preference ID"),
                    cols("user_id", "User"),
                    cols("muted", "Muted Categories"),
                    cols("quiet", "Quiet Hours (UTC)"),
                ],
                "/preferences",
            ))
            .build(),
        "templates" => AdminPage::new("Message Templates")
            .widget(table(
                vec![
                    col("id", "Template ID"),
                    cols("key", "Key"),
                    cols("locale", "Locale"),
                    cols("subject", "Subject"),
                ],
                "/templates",
            ))
            .build(),
        // ── Policy Studio pages ────────────────
        // Served from the SHARED page constructors (sentin8::rfw::policy_page
        // - identical definitions for every adopting service); the pilot's
        // local copies were consolidated. Row `id` = the policy-
        // set name / colon-joined tuple so the renderer's {id} substitution
        // resolves the aliases; the editor is generated per set with the
        // concrete name embedded in the native widget props.
        p if sentin8::rfw::policy_page("sentin8:post", p).is_some() => {
            // Unwrap-safe: the guard above proved Some.
            sentin8::rfw::policy_page("sentin8:post", p)
                .expect("policy_page checked in guard")
                .build()
        }
        // ── Relations (ReBAC) + attributes (ABAC) admin pages (/c) ──
        "relations" => AdminPage::new("Relations (ReBAC)")
            .widget(table_with_actions(
                vec![
                    col("subject_type", "Subject Type"),
                    col("subject_id", "Subject ID"),
                    col("relation", "Relation"),
                    col("object_type", "Object Type"),
                    col("object_id", "Object ID"),
                    cols("origin", "Origin"),
                ],
                "/relations",
                // Row id = colon-joined tuple (renderer substitutes {id});
                // the server-side alias splits it back into the five parts.
                vec![row_action_danger("Delete", "relations/{id}/delete")],
            ))
            .build(),
        "attributes" => AdminPage::new("Principal Attributes (ABAC)")
            .widget(table_with_actions(
                vec![
                    col("subject_id", "Subject ID"),
                    col("attr_key", "Attribute"),
                    cols("attr_value", "Value"),
                    cols("origin", "Origin"),
                ],
                "/attributes",
                // Row id = `subject_id:attr_key` (server-side alias splits).
                vec![row_action_danger("Delete", "attributes/{id}/delete")],
            ))
            .build(),
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };
    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(def)).unwrap(),
    ))
}

/// `GET /v1/admin/{resource}` - returns a JSON array of admin data rows.
/// Fetch admin data.
#[utoipa::path(
    get,
    path = "/v1/admin/{resource}",
    params(
        ("resource" = String, Path, description = "Admin data resource"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "The resource's rows for the RFW table", body = serde_json::Value),
        (status = 403, description = "Caller lacks a post read/admin scope"),
        (status = 404, description = "Unknown resource"),
    ),
    security(("sentin8:post:read" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a = crate::auth::require_any_scope(
        &state.config,
        &headers,
        &[
            "sentin8:post:read",
            "sentin8:post:write",
            "sentin8:sys:admin",
            "sentin8:sys:org:admin",
            "sentin8:sys:env:admin",
        ],
    )
    .await?;
    let env_id = q
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                "missing target_env_id".into(),
            )
        })?;
    // RLS: `inbox`/`gateways`/`dlq` are FORCE-RLS'd on (context_initialized,
    // env_id); set_config(…, true) is transaction-local, so the context +
    // queries run inside ONE explicit transaction on the same connection
    // (post DESIGN §6.4) - a bare-pool read hides every row ("No data.").
    let mut tx = state.pool.begin().await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("pool: {e}"),
        )
    })?;
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("context: {e}"),
            )
        })?;
    let rows: Vec<serde_json::Value> = match resource.as_str() {
        "messages" => sqlx::query("SELECT id::text, recipient_email, subject, delivered::text FROM inbox WHERE env_id = $1 ORDER BY created_at DESC LIMIT 100")
            .bind(env_id)
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| serde_json::json!({
                "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                "to": row.get::<Option<String>, &str>("recipient_email").unwrap_or_default(),
                "subject": row.get::<Option<String>, &str>("subject").unwrap_or_default(),
                "status": row.get::<Option<String>, &str>("delivered").unwrap_or_default(),
            })).collect()).unwrap_or_default(),
        "gateways" => sqlx::query("SELECT id::text, provider, channel, is_enabled::text FROM gateways WHERE env_id = $1 ORDER BY created_at DESC LIMIT 100")
            .bind(env_id)
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| serde_json::json!({
                "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                "name": row.get::<Option<String>, &str>("provider").unwrap_or_default(),
                "type": row.get::<Option<String>, &str>("channel").unwrap_or_default(),
                "status": row.get::<Option<String>, &str>("is_enabled").unwrap_or_default(),
            })).collect()).unwrap_or_default(),
        "dlq" => sqlx::query("SELECT id::text, inbox_id::text, channel, error FROM dlq WHERE env_id = $1 ORDER BY created_at DESC LIMIT 100")
            .bind(env_id)
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| serde_json::json!({
                "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                "inbox_id": row.get::<Option<String>, &str>("inbox_id").unwrap_or_default(),
                "channel": row.get::<Option<String>, &str>("channel").unwrap_or_default(),
                "error": row.get::<Option<String>, &str>("error").unwrap_or_default(),
            })).collect()).unwrap_or_default(),
        "preferences" => sqlx::query("SELECT id::text, user_id::text, muted_categories, quiet_hours_start::text, quiet_hours_end::text FROM notification_preferences WHERE env_id = $1 ORDER BY created_at DESC LIMIT 100")
            .bind(env_id)
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| serde_json::json!({
                "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                "user_id": row.get::<Option<String>, &str>("user_id").unwrap_or_default(),
                "muted": row.get::<Vec<String>, &str>("muted_categories").join(", "),
                "quiet": match (row.get::<Option<String>, &str>("quiet_hours_start"), row.get::<Option<String>, &str>("quiet_hours_end")) {
                    (Some(s), Some(e)) => format!("{s}:00-{e}:00"),
                    _ => "".to_string(),
                },
            })).collect()).unwrap_or_default(),
        "templates" => sqlx::query("SELECT id::text, template_key, locale, subject FROM templates WHERE env_id = $1 ORDER BY template_key, locale LIMIT 100")
            .bind(env_id)
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| serde_json::json!({
                "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                "key": row.get::<Option<String>, &str>("template_key").unwrap_or_default(),
                "locale": row.get::<Option<String>, &str>("locale").unwrap_or_default(),
                "subject": row.get::<Option<String>, &str>("subject").unwrap_or_default(),
            })).collect()).unwrap_or_default(),
        "policy-sets" => sqlx::query(
                r#"SELECT policy_set_name, origin, mode, version::text, enabled::text, length(policies)::text AS policies_len
                     FROM sys.policy_sets
                    WHERE service = 'sentin8:post' AND env_id = $1
                    ORDER BY policy_set_name LIMIT 100"#,
            )
            .bind(env_id)
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| serde_json::json!({
 // id = the set name - the RFW renderer substitutes {id} in
 // row-action endpoints.
                "id": row.get::<Option<String>, &str>("policy_set_name").unwrap_or_default(),
                "policy_set_name": row.get::<Option<String>, &str>("policy_set_name").unwrap_or_default(),
                "origin": row.get::<Option<String>, &str>("origin").unwrap_or_default(),
                "mode": row.get::<Option<String>, &str>("mode").unwrap_or_default(),
                "version": row.get::<Option<String>, &str>("version").unwrap_or_default(),
                "enabled": row.get::<Option<String>, &str>("enabled").unwrap_or_default(),
                "policies_len": row.get::<Option<String>, &str>("policies_len").unwrap_or_default(),
            })).collect()).unwrap_or_default(),
        "policy-decisions" => sqlx::query(
                r#"SELECT created_at::text, event
                     FROM audit_events
                    WHERE env_id = $1
                      AND service = 'post'
                      AND (event->>'action' = 'policy.deny' OR event->>'action' = 'policy.would_deny')
                    ORDER BY created_at DESC LIMIT 100"#,
            )
            .bind(env_id)
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| {
                let event: serde_json::Value = row.get("event");
                serde_json::json!({
                    "timestamp": row.get::<Option<String>, &str>("created_at").unwrap_or_default(),
                    "decision": event.get("action").cloned().unwrap_or(serde_json::json!("unknown")),
                    "action_id": event.get("action_id").cloned().unwrap_or(serde_json::json!("")),
                    "policy_set": event.get("policy_set").cloned().unwrap_or(serde_json::json!("")),
                    "reason": event.get("reason").cloned().unwrap_or(serde_json::json!("")),
                    "subject": event.get("subject").cloned().unwrap_or(serde_json::json!("")),
                })
            }).collect()).unwrap_or_default(),
        "relations" => sqlx::query(
                r#"SELECT subject_type, subject_id, relation, object_type, object_id, origin
                     FROM policy_relations
                    WHERE service = 'sentin8:post' AND env_id = $1
                    ORDER BY subject_type, subject_id, relation LIMIT 100"#,
            )
            .bind(env_id)
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| {
                let st = row.get::<Option<String>, &str>("subject_type").unwrap_or_default();
                let sid = row.get::<Option<String>, &str>("subject_id").unwrap_or_default();
                let rel = row.get::<Option<String>, &str>("relation").unwrap_or_default();
                let ot = row.get::<Option<String>, &str>("object_type").unwrap_or_default();
                let oid = row.get::<Option<String>, &str>("object_id").unwrap_or_default();
                serde_json::json!({
 // id = colon-joined tuple - the renderer's {id} token
 // feeds the single-segment delete alias.
                    "id": format!("{st}:{sid}:{rel}:{ot}:{oid}"),
                    "subject_type": st,
                    "subject_id": sid,
                    "relation": rel,
                    "object_type": ot,
                    "object_id": oid,
                    "origin": row.get::<Option<String>, &str>("origin").unwrap_or_default(),
                })
            }).collect()).unwrap_or_default(),
        "attributes" => sqlx::query(
                r#"SELECT subject_id, attr_key, attr_value::text, origin
                     FROM policy_principal_attrs
                    WHERE env_id = $1
                    ORDER BY subject_id, attr_key LIMIT 100"#,
            )
            .bind(env_id)
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| {
                let sid = row.get::<Option<String>, &str>("subject_id").unwrap_or_default();
                let key = row.get::<Option<String>, &str>("attr_key").unwrap_or_default();
                serde_json::json!({
 // id = `subject_id:attr_key` - the renderer's {id} token
 // feeds the single-segment delete alias.
                    "id": format!("{sid}:{key}"),
                    "subject_id": sid,
                    "attr_key": key,
                    "attr_value": row.get::<Option<String>, &str>("attr_value").unwrap_or_default(),
                    "origin": row.get::<Option<String>, &str>("origin").unwrap_or_default(),
                })
            }).collect()).unwrap_or_default(),
        _ => vec![],
    };
    tx.commit().await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("commit: {e}"),
        )
    })?;
    Ok(Json(serde_json::Value::Array(rows)))
}

fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}
fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: true,
        width: None,
        format: None,
    }
}
fn table(columns: Vec<WidgetDataTableColumn>, endpoint: &str) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions: vec![],
    })
}
fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions,
    })
}
#[allow(dead_code)]
fn row_action(label: &str, route: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: None,
    }
}
fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}
/// Destructive row action (danger styling) targeting a POST alias.
fn row_action_danger(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Danger,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}
#[allow(dead_code)]
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
#[allow(dead_code)]
fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("add".into()),
    }
}

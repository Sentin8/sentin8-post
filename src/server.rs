// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Post.

use std::sync::Arc;

use axum::routing::{get, post};

use crate::handlers::{self, AppState};

/// Build the service state inside the shell's `with_state` closure:
/// capped pool, clients, Shield engine consumption, relays, listeners.
pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let config = crate::config::PostConfig::from_env();

    // DBX : ONE pool under `sentin8_post_service` (NOBYPASSRLS) - the
    // send API writes post.inbox; the relay drains it under per-row tenant
    // context. The retired BYPASSRLS `sentin8_post_relay` role + relay pool
    // are gone.
    let pool = core.pool.clone();

    // Bus client (for producing notification.received events on View
    // delivery) - auth DESIGN §4.3f: the `post` CERTIFICATE
    // is the identity; the mint retries while the fleet boots.
    let bus_client = loop {
        match sentin8::bus::client::BusClient::for_workload(
            &config.sentin8_bus_url,
            &config.sentin8_auth_issuer,
            "post",
        )
        .await
        {
            Ok(c) => break c,
            Err(e) => {
                tracing::debug!(error = %e, "post bus client: certificate not ready yet");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };

    // Spawn the inbox relay - drains inbox → resolves channels → dispatches
    // and produces notification:received to Bus. The client stays local to
    // the relay; handlers emit events via the local outbox (§6.7), not the
    // Bus client.
    crate::inbox_relay::spawn(
        pool.clone(),
        bus_client.clone(),
        config.database_url.clone(),
    );

    // ── Sentin8:Policy ( pilot) ────────────────────────────────────
    // Load the service's policy sets; an unparsable policy text REFUSES TO
    // START (fail-closed at boot, design ). The hot-reload task consumes
    // the `policy` stream as a direct consumer - with its OWN
    // M2M workload (`sentin8:post-policy`, bus:consume). The producer client
    // below carries only bus:produce; reusing it made every consume 403
    // (COLD-START-1).
    // ── Sentin8:Policy (- shell-owned boot): the shell's
    // boot step 8 already booted the engine (load via the post-policy DCR
    // consumer, shared step-5 deps, hot-reload, stat emitter). Post only
    // CONSUMES the engine - no second engine or DCR registration here.
    let policy_engine = core.admin.policy.clone();

    // auth DESIGN §4.3f: boot-load the workload registry map (the
    // token-free authorization record) for the cert-first handler gate -
    // sys's post pusher presents the `sys-post` certificate on every
    // notification send; a bearer-only gate 401s it forever (the 92k/day
    // retry loop, CAPTCPU-1 item 1). Fail-open-with-warning on an
    // unreachable Valkey at boot - the bearer path (user/delegated)
    // serves while certificate-workload calls fail-closed until the
    // next boot (the map is normally published by enroll BEFORE
    // services start; func carries the same fallback).
    let workload_registry = match sentin8::auth::workload_registry::WorkloadMap::boot_load(
        "sentin8:post",
    )
    .await
    {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(error = %e, "post: workload registry map unavailable at boot - certificate-workload calls fail-closed until next boot");
            sentin8::auth::workload_registry::WorkloadMap::boot_load_empty("sentin8:post")
        }
    };

    let state = AppState {
        config: Arc::new(config),
        pool: core.pool,
        policy: policy_engine,
        workload_registry,
    };

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the standard
/// middleware stack; this adds ONLY routes (including the service's own
/// `/v1/health` - custom payload).
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        .route("/v1/health", get(handlers::health))
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        .route("/v1/messages", get(handlers::list_messages))
        .route("/v1/send", post(handlers::send_message))
        .route("/v1/messages/{id}", get(handlers::get_message))
        .route(
            "/v1/messages/{id}/content",
            get(handlers::get_message_content),
        )
        .route("/v1/messages/{id}/read", post(handlers::mark_message_read))
        .route("/v1/dlq", get(handlers::list_dlq))
        .route("/v1/dlq/{id}/replay", post(handlers::replay_dlq))
        .route(
            "/v1/gateways",
            get(handlers::list_gateways).post(handlers::create_gateway),
        )
        .route(
            "/v1/gateways/{id}",
            axum::routing::delete(handlers::delete_gateway),
        )
        // POST alias for RFW row_action_post (renderer only supports POST)
        .route(
            "/v1/gateways/{id}/delete",
            post(crate::rfw_aliases::gateway_delete),
        )
        // POST alias for message replay
        .route(
            "/v1/messages/{id}/replay",
            post(crate::rfw_aliases::message_replay),
        )
        .route("/v1/gateways/test", post(handlers::test_gateway))
        // ── Policy-sets admin API ────────────────────────
        .route(
            "/v1/admin/policy-sets",
            get(crate::policy_admin::list_policy_sets),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(crate::policy_admin::get_policy_set)
                .put(crate::policy_admin::put_policy_set)
                .delete(crate::policy_admin::delete_policy_set),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(crate::policy_admin::test_policy_set),
        )
        // RFW POST-alias row actions (Dash 28.14 - renderer is POST-only).
        .route(
            "/v1/admin/policy-sets/enforce",
            post(crate::policy_admin::admin_enforce_policy_set),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(crate::policy_admin::admin_shadow_policy_set),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(crate::policy_admin::admin_disable_policy_set),
        )
        // ── Relations + attributes admin API ────────────
        .route(
            "/v1/admin/relations",
            get(crate::policy_admin::list_relations)
                .put(crate::policy_admin::put_relation)
                .delete(crate::policy_admin::delete_relation),
        )
        .route(
            "/v1/admin/relations/check",
            get(crate::policy_admin::check_relation),
        )
        .route(
            "/v1/admin/attributes",
            get(crate::policy_admin::list_attributes)
                .put(crate::policy_admin::put_attribute)
                .delete(crate::policy_admin::delete_attribute),
        )
        // ── Policy Studio ─────────────────
        .route(
            "/v1/admin/policy-sets",
            post(crate::policy_admin::create_policy_set),
        )
        .route(
            "/v1/admin/policy-sets/{name}/save",
            post(crate::policy_admin::save_policy_set),
        )
        .route(
            "/v1/admin/policy-sets/{name}/{action}",
            post(crate::policy_admin::admin_path_action_policy_set),
        )
        .route(
            "/v1/admin/policy-decisions",
            get(crate::policy_admin::list_policy_decisions),
        )
        .route(
            "/v1/admin/relations/{id}/delete",
            post(crate::policy_admin::admin_delete_relation_path),
        )
        .route(
            "/v1/admin/attributes/{id}/delete",
            post(crate::policy_admin::admin_delete_attribute_path),
        )
}

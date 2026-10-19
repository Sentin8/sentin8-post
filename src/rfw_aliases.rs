// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Annotated RFW POST-alias wrappers (Dash 28.14): one annotated handler =
//! one path in the spec, so the second bindings of the gateway-delete and
//! message-replay handlers need their own wrapper annotations (same handler
//! body, alias path - OAPEC design §2 rule 3).

use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};

/// `POST /v1/gateways/{id}/delete` - RFW alias of `DELETE /v1/gateways/{id}`.
#[utoipa::path(
    post,
    path = "/v1/gateways/{id}/delete",
    params(("id" = uuid::Uuid, Path, description = "Gateway id")),
    responses(
        (status = 200, description = "Gateway deleted (same contract as DELETE /v1/gateways/{id})"),
        (status = 403, description = "Missing post:write scope (platform-tier deletes require sys:admin)"),
        (status = 404, description = "Unknown gateway"),
    ),
    security(("sentin8:post:write" = [])),
    tag = "post",
)]
pub async fn gateway_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::handlers::delete_gateway(State(state), headers, Path(id)).await
}

/// `POST /v1/messages/{id}/replay` - RFW alias of `POST /v1/dlq/{id}/replay`.
#[utoipa::path(
    post,
    path = "/v1/messages/{id}/replay",
    params(("id" = uuid::Uuid, Path, description = "DLQ message id")),
    responses(
        (status = 200, description = "Message replayed (same contract as POST /v1/dlq/{id}/replay)"),
        (status = 403, description = "Missing post:write scope"),
        (status = 404, description = "Unknown DLQ entry"),
    ),
    security(("sentin8:post:write" = [])),
    tag = "post",
)]
pub async fn message_replay(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::handlers::replay_dlq(State(state), headers, Path(id)).await
}

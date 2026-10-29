// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Auth token verification for Post.
//!
//! Re-exports the shared types from the sentin8-auth-client SDK and provides
//! thin wrappers matching the original Post call sites (taking `&PostConfig` + `&HeaderMap`).

use axum::http::{HeaderMap, StatusCode};

use crate::config::PostConfig;

pub use sentin8::auth::client::AuthContext;

/// Verify the Bearer token and return the auth context.
pub async fn verify_token(
    config: &PostConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    sentin8::auth::client::verify_bearer_token(&config.auth_client, headers).await
}

/// Verify the caller: certificate first (TLS-injected workload identity,
/// auth DESIGN §4.3f), Bearer token fallback (user/delegated flows).
/// Sys's post pusher presents the `sys-post` certificate on every
/// notification send - the bearer-only gate 401'd it forever (the
/// 92k/day retry loop item 1).
pub async fn verify_cert_or_token(
    registry: &sentin8::auth::workload_registry::WorkloadMap,
    config: &PostConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    // The TLS layer injects these ONLY after CA-verifying the presented
    // certificate (client-supplied copies are stripped before injection).
    let subject = headers
        .get("x-sentin8-client-cert-subject")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty());
    let Some(subject) = subject else {
        return verify_token(config, headers).await;
    };
    let Some(workload) = subject.strip_prefix("m2m-").filter(|w| !w.is_empty()) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("certificate CN '{subject}' is not a platform workload identity"),
        ));
    };
    let Some(rec) = registry.get(workload).await else {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("workload '{workload}' is not enrolled"),
        ));
    };
    if !rec.enabled {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("workload '{workload}' is disabled"),
        ));
    }
    // Synthetic request-scoped claims: the identity is the certificate
    // (valid until Acme-side expiry or registry revocation, observed
    // within the map's TTL). Nothing caches these.
    let now = chrono::Utc::now().timestamp();
    let (scope_str, vertical) = (rec.scopes.join(" "), rec.vertical.clone());
    Ok(AuthContext {
        claims: sentin8::auth::client::VerifiedClaims {
            sub: format!("m2m-{workload}"),
            iss: config.sentin8_auth_issuer.clone(),
            aud: String::new(),
            jti: "cert".to_string(),
            iat: now,
            exp: i64::MAX,
            token_tp: "m2m".to_string(),
            scope: scope_str,
            env_id: Some(sentin8::config::SYSTEM_ENV_ID.to_string()),
            email: None,
            act: None,
            vertical: Some(vertical),
            service_type: Some(rec.service_type.clone()),
        },
        workload: Some(sentin8::auth::client::WorkloadIdentity {
            workload: workload.to_string(),
            scopes: rec.scopes.clone(),
            vertical: Some(rec.vertical),
            service_type: Some(rec.service_type.clone()),
            thumbprint: headers
                .get("x-sentin8-client-cert-thumbprint")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string(),
        }),
    })
}

/// Require any of the given scopes (platform admins bypass).
pub async fn require_any_scope(
    config: &PostConfig,
    headers: &HeaderMap,
    scopes: &[&str],
) -> Result<AuthContext, (StatusCode, String)> {
    let a = verify_token(config, headers).await?;
    a.require_any_scope(scopes)?;
    Ok(a)
}

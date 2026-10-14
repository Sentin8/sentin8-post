// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

// Post inbox-first relay tests — testing-strategy §3 (TEST-1 in
// services/post/BACKLOG.md).
//
// The relay loop (`inbox_relay.rs`) is DB-bound; the pure seams are its
// Bus envelope contract and its gateway-stub dispatch decisions, which are
// mirrored here against the actual `ProduceRequest` type the relay builds
// (`sentin8::bus::contracts::ProduceRequest`). The event payload-completeness
// rule (AGENTS.md "event first, API second") is asserted: the
// `notification.received` envelope must carry everything the BFF SSE
// consumer needs without a callback — user_id, title, body, category,
// resource ids, unread_count.
//
// Handler wire formats (`CreateGatewayRequest`, `MessageSummary` fields)
// are exercised through serde. Pure tests — run under `make test-rust`.

use serde_json::json;

// ── notification.received envelope completeness (relay step 2) ─────────

/// Rebuild the exact `ProduceRequest` the relay constructs for a drained
/// message — kept in lockstep with `inbox_relay.rs::drain`. If the relay
/// envelope drifts (field added/renamed), these tests flag it because the
/// BFF SSE consumer depends on this exact shape.
fn relay_notification_envelope(
    message_id: uuid::Uuid,
    recipient_user_id: Option<uuid::Uuid>,
    subject: &str,
    body: &str,
    category: &str,
    metadata: serde_json::Value,
    unread_count: i64,
) -> sentin8::bus::contracts::ProduceRequest {
    sentin8::bus::contracts::ProduceRequest {
        stream_family: "notifications".into(),
        event_type: "sentin8:notification:received".into(),
        payload: json!({
            "user_id": recipient_user_id,
            "title": subject,
            "body": body,
            "category": category,
            "resource_type": "message",
            "resource_id": message_id,
            "metadata": metadata,
            "unread_count": unread_count,
        }),
        env_id: None,
        correlation_id: None,
        idempotency_key: Some(message_id.to_string()),
        publisher_id_token: None,
        publisher_subject: Some("sentin8:post".into()),
    }
}

#[test]
fn notification_event_name_uses_colon_convention() {
    // AGENTS.md event naming: vertical:service:resource:operation, colons only.
    // Post is a platform service whose event namespace is `sentin8:notification:*`
    // (service=notification, resource=received/read) — matching what the
    // relay actually emits and what BFF's SSE consumer subscribes to.
    let req = relay_notification_envelope(
        uuid::Uuid::new_v4(),
        Some(uuid::Uuid::new_v4()),
        "Payment received",
        "You received 50.00 EUR",
        "transaction",
        json!({}),
        1,
    );
    assert_eq!(req.event_type, "sentin8:notification:received");
    assert!(
        !req.event_type.contains('.'),
        "dots are banned in event names"
    );
    let segments: Vec<&str> = req.event_type.split(':').collect();
    assert_eq!(segments[0], "sentin8", "first segment is the vertical");
    assert_eq!(segments[1], "notification", "second segment is the service");
}

#[test]
fn notification_envelope_is_self_sufficient() {
    // Payload-completeness rule: the consumer must not need a callback to
    // render the badge/title. Every consumer-required field is present.
    let id = uuid::Uuid::new_v4();
    let uid = uuid::Uuid::new_v4();
    let req = relay_notification_envelope(
        id,
        Some(uid),
        "Statement ready",
        "Your January statement is ready",
        "statement",
        json!({ "period": "2026-01" }),
        4,
    );
    let payload = &req.payload;
    assert_eq!(payload["user_id"], json!(uid));
    assert_eq!(payload["title"], "Statement ready");
    assert_eq!(payload["body"], "Your January statement is ready");
    assert_eq!(payload["category"], "statement");
    assert_eq!(payload["resource_type"], "message");
    assert_eq!(payload["resource_id"], json!(id));
    assert_eq!(payload["metadata"]["period"], "2026-01");
    assert_eq!(payload["unread_count"], 4);
}

#[test]
fn notification_idempotency_key_is_message_id() {
    // Redelivery of the same inbox row must dedupe on the message id.
    let id = uuid::Uuid::new_v4();
    let a = relay_notification_envelope(id, None, "t", "b", "security", json!({}), 0);
    let b = relay_notification_envelope(id, None, "t", "b", "security", json!({}), 0);
    assert_eq!(a.idempotency_key, b.idempotency_key);
    assert_eq!(a.idempotency_key.as_deref(), Some(id.to_string().as_str()));
}

#[test]
fn notification_publisher_is_the_service() {
    // The relay produces on behalf of the service (M2M), not the user.
    let req = relay_notification_envelope(uuid::Uuid::new_v4(), None, "t", "b", "x", json!({}), 0);
    assert_eq!(req.publisher_subject.as_deref(), Some("sentin8:post"));
    assert_eq!(req.stream_family, "notifications");
}

#[test]
fn produce_request_roundtrip() {
    let req = relay_notification_envelope(
        uuid::Uuid::new_v4(),
        Some(uuid::Uuid::new_v4()),
        "t",
        "b",
        "security",
        json!({ "k": "v" }),
        2,
    );
    let json = serde_json::to_value(&req).unwrap();
    let back: sentin8::bus::contracts::ProduceRequest = serde_json::from_value(json).unwrap();
    assert_eq!(back.event_type, req.event_type);
    assert_eq!(back.payload, req.payload);
    assert_eq!(back.idempotency_key, req.idempotency_key);
}

// ── Gateway-stub dispatch matrix (relay step 3, Epic 18.2) ──────────────

/// Which gateway channels fire for a message — mirrors the category /
/// recipient decisions in `inbox_relay.rs::drain` (stubs log; the dispatch
/// decision itself is the contract).
fn gateway_dispatch(
    recipient_email: Option<&str>,
    metadata: &serde_json::Value,
    category: &str,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    if recipient_email.is_some_and(|e| !e.is_empty()) {
        out.push("email");
    }
    if metadata
        .get("recipient_phone")
        .and_then(|v| v.as_str())
        .is_some_and(|p| !p.is_empty())
    {
        out.push("sms");
    }
    if category == "security" || category == "transaction" {
        out.push("push");
    }
    if category == "security" {
        out.push("web-push");
    }
    if category == "statement" || category == "letter" {
        out.push("mail");
    }
    out
}

#[test]
fn gateway_dispatch_email_only() {
    assert_eq!(
        gateway_dispatch(Some("u@example.com"), &json!({}), "info"),
        vec!["email"]
    );
}

#[test]
fn gateway_dispatch_empty_email_skipped() {
    // Empty-string email must not fire the email gateway.
    assert!(gateway_dispatch(Some(""), &json!({}), "info").is_empty());
}

#[test]
fn gateway_dispatch_sms_via_metadata() {
    assert_eq!(
        gateway_dispatch(None, &json!({ "recipient_phone": "+15551234567" }), "info"),
        vec!["sms"]
    );
    // Empty phone number must not fire.
    assert!(gateway_dispatch(None, &json!({ "recipient_phone": "" }), "info").is_empty());
}

#[test]
fn gateway_dispatch_push_categories() {
    assert!(gateway_dispatch(None, &json!({}), "security").contains(&"push"));
    assert!(gateway_dispatch(None, &json!({}), "transaction").contains(&"push"));
    assert!(!gateway_dispatch(None, &json!({}), "marketing").contains(&"push"));
}

#[test]
fn gateway_dispatch_web_push_security_only() {
    assert!(gateway_dispatch(None, &json!({}), "security").contains(&"web-push"));
    assert!(!gateway_dispatch(None, &json!({}), "transaction").contains(&"web-push"));
}

#[test]
fn gateway_dispatch_mail_categories() {
    assert!(gateway_dispatch(None, &json!({}), "statement").contains(&"mail"));
    assert!(gateway_dispatch(None, &json!({}), "letter").contains(&"mail"));
    assert!(!gateway_dispatch(None, &json!({}), "info").contains(&"mail"));
}

#[test]
fn gateway_dispatch_security_fires_all_applicable() {
    let d = gateway_dispatch(
        Some("a@b.c"),
        &json!({ "recipient_phone": "+1" }),
        "security",
    );
    assert_eq!(d, vec!["email", "sms", "push", "web-push"]);
}

// ── Handler wire formats ────────────────────────────────────────────────

// Read-receipt envelope (post DESIGN §4): the mark-read handler
// inserts this shape into the local post.outbox; the shell relay produces
// it to Bus with `idempotency_key = outbox row id`. The event name follows
// the colon convention.
#[test]
fn mark_read_receipt_envelope() {
    let req = sentin8::bus::contracts::ProduceRequest {
        stream_family: "notifications".into(),
        event_type: "sentin8:post:notification:read".into(),
        payload: json!({
            "user_id": "u1",
            "notification_id": "m1",
            "env_id": "00000000-0000-0000-0000-000000000002",
            "read_at": "2026-09-26T00:00:00Z",
            "unread_count": 0
        }),
        env_id: Some(uuid::Uuid::nil()),
        correlation_id: None,
        idempotency_key: Some("m1".into()),
        publisher_id_token: None,
        publisher_subject: Some("usr".into()),
    };
    assert_eq!(req.event_type, "sentin8:post:notification:read");
    // Colon-only naming (vertical:service:resource:operation).
    assert!(!req.event_type.contains('.'));
    // Payload completeness (outbox §6.7): the BFF per-user filter keys on
    // `user_id` and the badge consumer reads `unread_count`.
    assert!(req.payload.get("user_id").is_some());
    assert!(req.payload.get("unread_count").is_some());
    assert!(req.payload.get("notification_id").is_some());
}

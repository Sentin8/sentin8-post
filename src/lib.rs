// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Post - multi-channel message delivery service.

#![deny(missing_docs)]

/// Admin UI (RFW) handlers.
pub mod admin_ui;
/// Produce/consume authentication helpers.
pub mod auth;
/// Environment configuration.
pub mod config;
/// HTTP handlers - message send, delivery status, gateways.
pub mod handlers;
/// Inbox relay - drains the inbox and delivers messages.
pub mod inbox_relay;
/// OpenAPI spec assembly.
pub mod openapi;
/// Shield (Sentin8:Policy) integration - shared bridge re-exports.
pub mod policy;
/// Shield policy-admin surface handlers.
pub mod policy_admin;
/// Policy hot-reload consumer.
pub mod policy_reloader;
/// Service self-registration declarations.
pub mod registration;
pub mod rfw_aliases;
/// Axum router and server.
pub mod server;

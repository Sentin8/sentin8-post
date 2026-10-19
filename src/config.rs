// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Post configuration loaded from environment variables.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Debug, Clone)]
/// Configuration for post.
pub struct PostConfig {
    /// Owned by the shell (SENTIN8_POST_PORT / database fallback chain) -
    /// kept for parity with the other config fields.
    #[allow(dead_code)]
    /// The port.
    pub port: u16,
    /// Owned by the shell (the service state receives the shell's pool).
    #[allow(dead_code)]
    /// The database URL.
    pub database_url: String,
    #[allow(dead_code)]
    /// The valkey URL.
    pub valkey_url: String,
    /// The sentin8 auth issuer.
    pub sentin8_auth_issuer: String,
    #[allow(dead_code)]
    /// The sentin8 auth JWKS URL.
    pub sentin8_auth_jwks_url: String,
    /// The sentin8 bus URL.
    pub sentin8_bus_url: String,
    /// The auth client.
    pub auth_client: AuthClient,
}

impl PostConfig {
    /// Handle from env.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        let database_url = env::var("SENTIN8_POST_DATABASE_URL").unwrap_or_else(|_| {
            env::var("DATABASE_URL").unwrap_or_else(|_| {
                sentin8::config::Sentin8Config::default_database_url().to_string()
            })
        });
        Self {
            port: env::var("SENTIN8_POST_PORT")
                .expect("SENTIN8_POST_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_POST_PORT must be a valid u16"),
            database_url,
            valkey_url: env::var("SENTIN8_POST_VALKEY_URL").unwrap_or_else(|_| {
                sentin8::config::Sentin8Config::default_valkey_url().to_string()
            }),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER")
                .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
        }
    }
}

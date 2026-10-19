// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Policy integration for Post ( pilot).
//!
//! Thin re-export of the shared bridge (`sentin8::shield::runtime`) - the
//! consolidated implementation every service uses. Post (as pilot) uses the
//! full step-5 evaluation: live roles + relation slice +
//! principal attributes , each degrading independently (fail-closed).
//!
//! - `engine` / `spawn_hot_reload` - boot + hot-reload (/);
//! - `require_policy` - step 5 glue: evaluate + convert enforced deny to 403;
//! - `policy_bus_client` - the M2M DCR-backed Bus consumer client.

#[allow(unused_imports)]
pub use sentin8::shield::runtime::{
    boot_full, check_policy, init_shared_deps, policy_bus_client, request_ctx, spawn_hot_reload,
};
pub use sentin8::shield::PolicyEngine as Engine;

/// Step 5 for post: the shared FULL evaluation (live effective scopes +
/// roles + relation slice + principal attributes) via the shared deps
/// initialized at boot. `headers` must be the request's HeaderMap so the
/// raw Bearer token can drive live identity resolution.
pub use sentin8::shield::runtime::require_policy;

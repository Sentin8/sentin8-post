// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Sentin8:Post.
//!
//! Output via `--print-registration` flag. The CLI runs the binary with this
//! flag and consumes the JSON to register the service in the platform DB.
//! See the service design docs.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, PgRole, PolicySetDecl, Registration, RelationDecl,
    SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:post:read,sentin8:post:write",
    role: "sentin8_post_service",
    bypass_rls: false,
    database: "sentin8",
    cross_schema_grants: &[],
}];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "messages",
        label: "Messages",
        ui_endpoint: "/v1/admin/ui/messages",
        data_endpoint: "/v1/admin/messages",
        icon: "0xe3c3",
    },
    AdminUiPage {
        route: "gateways",
        label: "Gateways",
        ui_endpoint: "/v1/admin/ui/gateways",
        data_endpoint: "/v1/admin/gateways",
        icon: "0xe542",
    },
    AdminUiPage {
        route: "dlq",
        label: "DLQ",
        ui_endpoint: "/v1/admin/ui/dlq",
        data_endpoint: "/v1/admin/dlq",
        icon: "0xe238",
    },
    AdminUiPage {
        route: "preferences",
        label: "Preferences",
        ui_endpoint: "/v1/admin/ui/preferences",
        data_endpoint: "/v1/admin/preferences",
        icon: "0xe7f7",
    },
    AdminUiPage {
        route: "templates",
        label: "Templates",
        ui_endpoint: "/v1/admin/ui/templates",
        data_endpoint: "/v1/admin/templates",
        icon: "0xe245",
    },
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
    AdminUiPage {
        route: "relations",
        label: "Relations",
        ui_endpoint: "/v1/admin/ui/relations",
        data_endpoint: "/v1/admin/relations",
        icon: "0xe572",
    },
    AdminUiPage {
        route: "attributes",
        label: "Attributes",
        ui_endpoint: "/v1/admin/ui/attributes",
        data_endpoint: "/v1/admin/attributes",
        icon: "0xe8d3",
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");
const SQL_2_PREFERENCES_TEMPLATES: &str = include_str!("../sql/v2_preferences_templates.sql");

/// Default declarative policy sets (Sentin8:Policy design /):
/// action-granular scope permits over the LIVE effective scope set. Seeded
/// `origin='platform'`, `mode='enforced'` ( - step 5 is
/// the only gate; shadow is the emergency one-UPDATE rollback lever only).
const POLICIES: &[PolicySetDecl] = &[
    PolicySetDecl {
        policy_set_name: "scope-mirror",
        description: "Action-granular scope permits for sentin8:post over the LIVE effective scope set. Enforced - step 5 is the only gate.",
        policies: "permit(principal, action == Action::\"sentin8:post:read\", resource) when { principal.scopes.contains(\"sentin8:post:read\") };\npermit(principal, action == Action::\"sentin8:post:read\", resource) when { principal.scopes.contains(\"sentin8:post:admin\") };\npermit(principal, action == Action::\"sentin8:post:write\", resource) when { principal.scopes.contains(\"sentin8:post:write\") };\npermit(principal, action == Action::\"sentin8:post:write\", resource) when { principal.scopes.contains(\"sentin8:post:admin\") };\npermit(principal, action == Action::\"sentin8:post:policy:read\", resource) when { principal.scopes.contains(\"sentin8:post:policy:read\") };\npermit(principal, action == Action::\"sentin8:post:policy:write\", resource) when { principal.scopes.contains(\"sentin8:post:policy:write\") };",
        schema: None,
        mode: "enforced",
        default_enabled: true,
    },
];

/// Default ReBAC relation tuples - none for post today; the
/// env admin authors their own graph via the relations admin API.
const RELATIONS: &[RelationDecl] = &[];

/// Serialize the utoipa OpenAPI spec (used for the `all` and `openapi` sections).
fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::PostOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section as a standalone JSON value.
/// M2M DCR workload grants (self-registration ): this
/// service's own `certless:<workload>` rows, upserted by `vertical enroll`.
/// The static auth seed is retired - this declaration is the ONLY
/// provisioning path ( "DCR is dynamic").
/// Cover BOTH the full-identity `-policy` spelling (policy_bus_client) and
/// the bare `{short}-policy` spelling (stat_emit); the gate's superset
/// check admits any requested subset.
const M2M_GRANTS: &[sentin8::registration::M2mGrant] = &[
    sentin8::registration::M2mGrant {
        workload: "post-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:post",
        scopes: &["sentin8:bus:produce"],
    },
    sentin8::registration::M2mGrant {
        workload: "post",
        scopes: &["sentin8:bus:produce"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:post-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "post-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    // TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md §VDC.7): the database-free HostContextResolver’s resolve workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    sentin8::registration::M2mGrant {
        workload: "sentin8-post-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// Handle print.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:post",
        subdomain: "post",
        health_path: "/v1/health",
        // Admin scope declarations for the role registry: the `sentin8:post:admin`
        // role carries the granular scopes its handlers gate on
        // (`sentin8:post:read`, `sentin8:post:write`). `sentin8:post:admin` itself is a role NAME,
        // not a scope the handlers accept - without the granular entries
        // the provisioned role would carry a scope no handler checks.
        admin_scopes: &[
            AdminScope::Tuple("sentin8:post:admin", "sentin8:post:read"),
            AdminScope::Tuple("sentin8:post:admin", "sentin8:post:write"),
            // Policy-admin surface (policy design ; per-service
            // scope) - the scope-mirror set (line ~81) mirrors these two
            // actions, so the provisioned admin role must carry them.
            // Incident : the pair was missing here (every other
            // service registers it), so `GET /v1/admin/policy-sets` denied
            // 403 for the org admin - the e2e policy suite could not run.
            AdminScope::Tuple("sentin8:post:admin", "sentin8:post:policy:read"),
            AdminScope::Tuple("sentin8:post:admin", "sentin8:post:policy:write"),
        ],
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Post",
            icon: "0xe3c3",
            service_flag: "post",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![
            SqlMigration {
                version: 1,
                name: "init",
                sql: SQL_1_INIT,
            },
            SqlMigration {
                version: 2,
                name: "preferences_templates",
                sql: SQL_2_PREFERENCES_TEMPLATES,
            },
        ],
        pg_roles: PG_ROLES,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}

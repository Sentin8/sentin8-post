-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:Post — multi-channel message delivery service.
--
-- Sentin8:Post owns four tables:
--   post.inbox       — the transactional inbox (producers INSERT here)
--   post.deliveries  — per-channel delivery attempts
--   post.gateways    — configurable gateways at sys/org/env scope
--   post.dlq         — dead-letter queue for exhausted retries
--
-- Producers (Sentin8:Auth, Bank8:Ledger, Bank8:Payments, Sentin8:Sys, etc.) INSERT into post.inbox
-- in the same Sentin8:DB transaction as their domain change. Sentin8:Post's relay
-- (a background task inside post) drains the inbox via
-- LISTEN/NOTIFY, resolves the delivery channel, and dispatches.
--
-- See design/sentin8-post-technical-design.md.

-- ── post.inbox ────────────────────────────────────────────────────────
CREATE SCHEMA IF NOT EXISTS post;
CREATE TABLE IF NOT EXISTS post.inbox (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id               UUID NOT NULL,
    stream_family        TEXT NOT NULL,
    message_type         TEXT NOT NULL,
    category             TEXT NOT NULL DEFAULT 'system' CHECK (category IN ('transaction', 'security', 'marketing', 'system')),
    priority             TEXT NOT NULL DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high')),
    recipient_user_id    UUID,
    recipient_email      TEXT,
    recipient_phone      TEXT,
    recipient_device_token TEXT,
    subject              TEXT NOT NULL,
    body                 TEXT NOT NULL,
    body_format          TEXT NOT NULL DEFAULT 'text' CHECK (body_format IN ('text', 'html', 'markdown')),
    metadata             JSONB NOT NULL DEFAULT '{}',
    delivered            BOOLEAN NOT NULL DEFAULT false,
    delivered_at         TIMESTAMPTZ,
    read_at              TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_post_inbox_undelivered
    ON post.inbox (created_at)
    WHERE delivered = false;

CREATE INDEX IF NOT EXISTS idx_post_inbox_env
    ON post.inbox (env_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_post_inbox_recipient
    ON post.inbox (recipient_user_id)
    WHERE recipient_user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_post_inbox_unread
    ON post.inbox (env_id, recipient_user_id)
    WHERE read_at IS NULL;

-- ── post.deliveries ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS post.deliveries (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    inbox_id          UUID NOT NULL REFERENCES post.inbox(id) ON DELETE CASCADE,
    env_id            UUID NOT NULL,
    channel           TEXT NOT NULL CHECK (channel IN ('view', 'email', 'sms', 'push', 'web_push', 'mail')),
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'delivered', 'failed', 'dlq')),
    gateway_message_id TEXT,
    retry_count       INTEGER NOT NULL DEFAULT 0,
    max_retries       INTEGER NOT NULL DEFAULT 3,
    error             TEXT,
    next_retry_at     TIMESTAMPTZ,
    delivered_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_post_deliveries_inbox ON post.deliveries (inbox_id);
-- One delivery row per (inbox, channel): the retry machinery re-attempts
-- onto the SAME row (retry_count accumulates; post DESIGN §5/§10) — a
-- re-drain of an inbox row with a scheduled retry must not duplicate rows.
CREATE UNIQUE INDEX IF NOT EXISTS uq_post_deliveries_inbox_channel
    ON post.deliveries (inbox_id, channel);
CREATE INDEX IF NOT EXISTS idx_post_deliveries_retry ON post.deliveries (next_retry_at)
    WHERE status = 'pending' AND next_retry_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_post_deliveries_env ON post.deliveries (env_id);

-- ── post.gateways ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS post.gateways (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL,
    scope       TEXT NOT NULL CHECK (scope IN ('sys', 'org', 'env')),
    channel     TEXT NOT NULL CHECK (channel IN ('email', 'sms', 'push', 'web_push', 'mail')),
    provider    TEXT NOT NULL,
    config      JSONB NOT NULL DEFAULT '{}',
    is_enabled  BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_post_gateways_scope ON post.gateways (scope, env_id, channel);

-- ── post.dlq ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS post.dlq (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    inbox_id     UUID NOT NULL REFERENCES post.inbox(id) ON DELETE CASCADE,
    env_id       UUID NOT NULL,
    channel      TEXT NOT NULL,
    error        TEXT NOT NULL,
    retry_count  INTEGER NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_post_dlq_env ON post.dlq (env_id, created_at DESC);
-- ── RLS ────────────────────────────────────────────────────────────────
-- DBX (§6.7): post.inbox is written ONLY by Post's send API (running under
-- `sentin8_post_service`); the producing service's identity arrives with the
-- verified M2M token — no PG-role-derived stream-family pattern. Tenant
-- isolation stays the env_id match.
ALTER TABLE post.inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE post.inbox FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS post_inbox_select ON post.inbox;
CREATE POLICY post_inbox_select ON post.inbox FOR SELECT
    USING (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

DROP POLICY IF EXISTS post_inbox_insert ON post.inbox;
CREATE POLICY post_inbox_insert ON post.inbox FOR INSERT
    WITH CHECK (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

DROP POLICY IF EXISTS post_inbox_update ON post.inbox;
CREATE POLICY post_inbox_update ON post.inbox FOR UPDATE
    USING (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

-- post.deliveries, post.dlq: tenant-scoped (Sentin8:Post operators read these).
ALTER TABLE post.deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE post.deliveries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS post_deliveries_select ON post.deliveries;
CREATE POLICY post_deliveries_select ON post.deliveries FOR SELECT
    USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS post_deliveries_insert ON post.deliveries;
CREATE POLICY post_deliveries_insert ON post.deliveries FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS post_deliveries_update ON post.deliveries;
CREATE POLICY post_deliveries_update ON post.deliveries FOR UPDATE
    USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

ALTER TABLE post.dlq ENABLE ROW LEVEL SECURITY;
ALTER TABLE post.dlq FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS post_dlq_select ON post.dlq;
CREATE POLICY post_dlq_select ON post.dlq FOR SELECT
    USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS post_dlq_insert ON post.dlq;
CREATE POLICY post_dlq_insert ON post.dlq FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- post.gateways: scope-based RLS — sys visible to org admins, org to org members, env to env members.
ALTER TABLE post.gateways ENABLE ROW LEVEL SECURITY;
ALTER TABLE post.gateways FORCE ROW LEVEL SECURITY;
-- Gateway tiers (post DESIGN §5): every row is env-pinned (sys/org rows
-- live in the system env, env rows in the target env — the handler sets
-- the context to the same env it binds the row to). Platform-tier rows
-- (sys/org) additionally require the platform-admin scope stamp on the
-- mutating context — the RLS mirror of the handler's `sentin8:sys:admin`
-- 403 gate. The former `sentin8_bypass_rls()` branches are dead (§6.7 —
-- no role carries BYPASSRLS) and removed.
DROP POLICY IF EXISTS post_gateways_select ON post.gateways;
CREATE POLICY post_gateways_select ON post.gateways FOR SELECT
    USING (sentin8_context_initialized()
           AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS post_gateways_insert ON post.gateways;
CREATE POLICY post_gateways_insert ON post.gateways FOR INSERT
    WITH CHECK (sentin8_context_initialized()
                AND env_id = sentin8_current_env_id()
                AND (scope = 'env'
                     OR sentin8_has_scope('sentin8:sys:admin')));
DROP POLICY IF EXISTS post_gateways_update ON post.gateways;
CREATE POLICY post_gateways_update ON post.gateways FOR UPDATE
    USING (sentin8_context_initialized()
           AND env_id = sentin8_current_env_id()
           AND (scope = 'env'
                OR sentin8_has_scope('sentin8:sys:admin')));
DROP POLICY IF EXISTS post_gateways_delete ON post.gateways;
CREATE POLICY post_gateways_delete ON post.gateways FOR DELETE
    USING (sentin8_context_initialized()
           AND env_id = sentin8_current_env_id()
           AND (scope = 'env'
                OR sentin8_has_scope('sentin8:sys:admin')));

-- ── Owner-side env helpers (RLS drain discipline) ─────────────────────
-- `post.inbox` is FORCE-RLS'd: the in-process relay task has NO tenant
-- context of its own, so a bare-pool SELECT silently returns 0 rows and
-- the relay drains NOTHING (same incident class as the outbox relay,
-- architecture-principles §6.7 / crates/bus/outbox 2026-09-23). The
-- owner-side SECURITY DEFINER helpers below return only env UUIDs +
-- ids (no row content) so the relay can set per-env context and drain
-- each row's read/write under it (post DESIGN §5).
CREATE OR REPLACE FUNCTION post.post_undelivered_envs() RETURNS TABLE (env_id UUID)
LANGUAGE plpgsql SECURITY DEFINER AS $fn$
BEGIN
    RETURN QUERY SELECT DISTINCT i.env_id FROM post.inbox i WHERE i.delivered = false;
END;
$fn$;

CREATE OR REPLACE FUNCTION post.post_due_retry_rows(p_limit INT)
    RETURNS TABLE (inbox_id UUID, env_id UUID, channel TEXT)
LANGUAGE plpgsql SECURITY DEFINER AS $fn$
BEGIN
    RETURN QUERY
        SELECT d.inbox_id, d.env_id, d.channel
          FROM post.deliveries d
         WHERE d.status = 'pending' AND d.next_retry_at <= now()
         ORDER BY d.next_retry_at
         LIMIT p_limit;
END;
$fn$;

-- ── LISTEN/NOTIFY trigger ──────────────────────────────────────────────
CREATE OR REPLACE FUNCTION post.post_notify_inbox() RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('post_inbox_changed', '');
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS post_inbox_notify_trigger ON post.inbox;
CREATE TRIGGER post_inbox_notify_trigger
    AFTER INSERT ON post.inbox
    FOR EACH ROW
    EXECUTE FUNCTION post.post_notify_inbox();

-- ── Grants (DBX) ──
-- post.inbox is written by Post's send API AND by the listed inbox-first
-- producer sys (invitation sent/accepted post-mail — sys DESIGN §2):
-- a single, explicitly declared producer INSERT grant. post.deliveries/dlq
-- by the in-post relay — under `sentin8_post_service`. The
-- `sentin8_post_relay` BYPASSRLS role is RETIRED (§6.7).
GRANT USAGE ON SCHEMA post TO sentin8_post_service;
GRANT SELECT, INSERT, UPDATE ON post.inbox TO sentin8_post_service;
GRANT SELECT, INSERT, UPDATE ON post.deliveries TO sentin8_post_service;
GRANT SELECT, INSERT ON post.dlq TO sentin8_post_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON post.gateways TO sentin8_post_service;
-- Producers do NOT write post.inbox directly (DBX, principles §6.7):
-- each service enqueues into its own local post_outbox and its pusher
-- calls POST /v1/send with its own M2M token (Shield post:write). The
-- former cross-schema INSERT grant for sentin8_sys_service is retired.


-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: post.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("post").
CREATE TABLE IF NOT EXISTS post.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    -- WARN-5 backoff column (matches the SDK outbox DDL): a retryable
    -- failure parks the row until this timestamp.
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_post_outbox_unrelayed
    ON post.outbox (created_at) WHERE relayed = false;
ALTER TABLE post.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE post.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON post.outbox;
CREATE POLICY outbox_select ON post.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON post.outbox;
CREATE POLICY outbox_insert ON post.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON post.outbox;
CREATE POLICY outbox_update ON post.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION post.post_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('post_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON post.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON post.outbox
    FOR EACH ROW
    EXECUTE FUNCTION post.post_notify_outbox();


-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("post").
CREATE TABLE IF NOT EXISTS post.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_post_audit_journal_unpushed
    ON post.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE post.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE post.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON post.audit_journal;
CREATE POLICY audit_journal_dml ON post.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- ── Grants (after every table exists — GRANT on a not-yet-created table
-- aborts the whole init migration on a fresh bootstrap) ────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON post.outbox TO sentin8_post_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON post.audit_journal TO sentin8_post_service;

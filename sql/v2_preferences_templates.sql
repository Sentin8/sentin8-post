-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Post
-- SPDX-License-Identifier: Apache-2.0

-- ── post.notification_preferences (POST-5) ────────────────────────────
-- Per-user delivery preferences: muted categories and quiet hours. The
-- fan-out filter consults this table in the relay before external
-- channels attempt; the View channel (in-app) always delivers so the
-- user never loses the record of truth.
CREATE TABLE IF NOT EXISTS post.notification_preferences (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    user_id       UUID NOT NULL,
    muted_categories TEXT[] NOT NULL DEFAULT '{}',
    quiet_hours_start INT,
    quiet_hours_end   INT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, user_id)
);

ALTER TABLE post.notification_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE post.notification_preferences FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS post_prefs_dml ON post.notification_preferences;
CREATE POLICY post_prefs_dml ON post.notification_preferences
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON post.notification_preferences TO sentin8_post_service;

-- ── post.templates (POST-7) ───────────────────────────────────────────
-- Branded message templates: per (env, key, locale) rendered with
-- `{{var}}` substitution. Branding (`primary_color`, `logo_url`) rides
-- the render context resolved from `sys.branding` at delivery time —
-- the template variables, not the gateway, carry the branding.
CREATE TABLE IF NOT EXISTS post.templates (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    template_key  TEXT NOT NULL,
    locale        TEXT NOT NULL DEFAULT 'en',
    subject       TEXT NOT NULL,
    body          TEXT NOT NULL,
    body_format   TEXT NOT NULL DEFAULT 'text' CHECK (body_format IN ('text', 'html', 'markdown')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, template_key, locale)
);

ALTER TABLE post.templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE post.templates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS post_templates_dml ON post.templates;
CREATE POLICY post_templates_dml ON post.templates
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON post.templates TO sentin8_post_service;

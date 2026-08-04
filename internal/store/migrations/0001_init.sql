-- Nuclei Security Center beta baseline.
-- Fresh deployments only: alpha databases are intentionally not upgradeable.
-- This schema is the lossless final state of the alpha migration chain.

CREATE TABLE app_settings (
    id boolean DEFAULT true NOT NULL,
    retention_enabled boolean DEFAULT false NOT NULL,
    scan_retention_days integer,
    retention_include_adhoc boolean DEFAULT false NOT NULL,
    updated_by text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT app_settings_id_check CHECK (id)
);

CREATE TABLE auth_flows (
    state text NOT NULL,
    nonce text NOT NULL,
    pkce_verifier text NOT NULL,
    return_to text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE TABLE finding_lifecycle (
    id bigint NOT NULL,
    dedup_key text NOT NULL,
    template_id text NOT NULL,
    name text,
    severity text,
    host text,
    matched_at text,
    type text,
    cve text[] DEFAULT '{}'::text[] NOT NULL,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    first_seen_scan uuid,
    last_seen_scan uuid,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    latest_occurrence_id bigint,
    disposition_note text,
    disposition_by text,
    disposition_at timestamp with time zone,
    disposition text DEFAULT 'none'::text NOT NULL,
    accept_expires_at timestamp with time zone,
    recast_severity text,
    times_mitigated integer DEFAULT 0 NOT NULL,
    recast_note text,
    recast_by text,
    recast_at timestamp with time zone,
    last_covering_scan uuid,
    result_discriminator text DEFAULT ''::text NOT NULL,
    endpoint_key text DEFAULT ''::text NOT NULL,
    CONSTRAINT finding_lifecycle_disposition_chk CHECK ((disposition = ANY (ARRAY['none'::text, 'false_positive'::text, 'accepted'::text]))),
    CONSTRAINT finding_lifecycle_recast_chk CHECK (((recast_severity IS NULL) OR (recast_severity = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'info'::text]))))
);

COMMENT ON COLUMN finding_lifecycle.result_discriminator IS 'SHA-256 of stable matcher/extractor/extracted-result identity; empty for ordinary findings';

COMMENT ON COLUMN finding_lifecycle.endpoint_key IS 'Canonical host:port derived from matched_at for template+endpoint coverage';

CREATE SEQUENCE finding_lifecycle_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE finding_lifecycle_id_seq OWNED BY finding_lifecycle.id;

CREATE TABLE findings (
    id bigint NOT NULL,
    scan_id uuid NOT NULL,
    template_id text NOT NULL,
    name text,
    severity text,
    host text,
    matched_at text,
    type text,
    raw jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    cve text[] DEFAULT '{}'::text[] NOT NULL,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    target_id uuid,
    dedup_key text NOT NULL,
    finding_id bigint,
    raw_line text,
    result_discriminator text DEFAULT ''::text NOT NULL
);

COMMENT ON COLUMN findings.target_id IS 'Denormalized scan scope for indexed lifecycle projection/filtering; constrained to scans.target_id when non-NULL';

COMMENT ON COLUMN findings.result_discriminator IS 'SHA-256 of stable matcher/extractor/extracted-result identity; empty for ordinary findings';

CREATE SEQUENCE findings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE findings_id_seq OWNED BY findings.id;

CREATE TABLE scan_policies (
    id uuid NOT NULL,
    name text NOT NULL,
    template_set_id uuid NOT NULL,
    rate_limit integer,
    concurrency integer,
    timeout_sec integer,
    max_host_error integer,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    discovery_enabled boolean DEFAULT true NOT NULL,
    discovery_ports text,
    discovery_timeout_sec integer,
    discovery_rate integer,
    discovery_probe_timeout_ms integer,
    discovery_retries integer,
    discovery_scan_type text,
    discovery_host_discovery boolean,
    CONSTRAINT scan_policies_discovery_scan_type_check CHECK ((discovery_scan_type = ANY (ARRAY['syn'::text, 'connect'::text])))
);

COMMENT ON TABLE scan_policies IS 'Reusable target-independent scan configuration: template set plus Nuclei/discovery knobs';

COMMENT ON COLUMN scan_policies.discovery_host_discovery IS 'Whether naabu runs a host-discovery pass before port scanning; NULL preserves the scan-type default';

CREATE TABLE scanner_nodes (
    id uuid NOT NULL,
    name text NOT NULL,
    endpoint text NOT NULL,
    token text NOT NULL,
    cidrs text[] DEFAULT '{}'::text[] NOT NULL,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tls_server_ca text DEFAULT ''::text NOT NULL,
    tls_client_cert text DEFAULT ''::text NOT NULL,
    tls_client_key text DEFAULT ''::text NOT NULL,
    templates_synced_at timestamp with time zone
);

CREATE TABLE scans (
    id uuid NOT NULL,
    node_scan_id text,
    state text NOT NULL,
    spec jsonb NOT NULL,
    nuclei_version text,
    templates_commit text,
    error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    target_id uuid,
    template_set_id uuid,
    source text DEFAULT 'adhoc'::text NOT NULL,
    schedule_id uuid,
    raw_object_key text,
    log_object_key text,
    node_id uuid,
    scan_policy_id uuid,
    discovered_targets text[],
    covered_endpoints jsonb,
    coverage_warning text,
    skipped_finding_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT scans_covered_endpoints_array CHECK (((covered_endpoints IS NULL) OR (jsonb_typeof(covered_endpoints) = 'array'::text))),
    CONSTRAINT scans_skipped_finding_count_check CHECK ((skipped_finding_count >= 0))
);

COMMENT ON COLUMN scans.covered_endpoints IS 'Successful Nuclei request evidence as [{template_id, endpoint(host:port)}]; NULL means unknown';

COMMENT ON COLUMN scans.coverage_warning IS 'Fail-closed request-trace diagnostic surfaced on scan detail';

CREATE TABLE schedules (
    id uuid NOT NULL,
    name text NOT NULL,
    cron text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    next_run_at timestamp with time zone,
    last_run_at timestamp with time zone,
    last_scan_id uuid,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    scan_policy_id uuid NOT NULL,
    target_id uuid NOT NULL
);

COMMENT ON COLUMN schedules.target_id IS 'Approved stored target selected independently from the reusable scan policy';

CREATE TABLE service_accounts (
    id uuid NOT NULL,
    name text NOT NULL,
    role text NOT NULL,
    token_hash text NOT NULL,
    token_prefix text NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone
);

CREATE TABLE sessions (
    id text NOT NULL,
    subject text NOT NULL,
    email text,
    name text,
    roles text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE TABLE targets (
    id uuid NOT NULL,
    name text NOT NULL,
    hosts text[] NOT NULL,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE template_set_exclusions (
    template_set_id uuid NOT NULL,
    template_id text NOT NULL,
    added_by text,
    added_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE template_set_members (
    template_set_id uuid NOT NULL,
    template_id text NOT NULL,
    added_by text,
    added_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE template_sets (
    id uuid NOT NULL,
    name text NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    mode text DEFAULT 'exact'::text NOT NULL,
    CONSTRAINT template_sets_mode_check CHECK ((mode = ANY (ARRAY['exact'::text, 'all'::text, 'exclude'::text])))
);

CREATE TABLE template_sync_runs (
    id uuid NOT NULL,
    started_at timestamp with time zone NOT NULL,
    finished_at timestamp with time zone,
    status text NOT NULL,
    ref_before text,
    ref_after text,
    added integer DEFAULT 0 NOT NULL,
    removed integer DEFAULT 0 NOT NULL,
    updated integer DEFAULT 0 NOT NULL,
    skipped integer DEFAULT 0 NOT NULL,
    error text,
    templates_commit text,
    template_count integer,
    CONSTRAINT template_sync_runs_status_check CHECK ((status = ANY (ARRAY['running'::text, 'success'::text, 'failed'::text]))),
    CONSTRAINT template_sync_runs_template_count_check CHECK ((template_count >= 0))
);

CREATE TABLE templates (
    id text NOT NULL,
    source text NOT NULL,
    path text NOT NULL,
    yaml text NOT NULL,
    content_sha256 text NOT NULL,
    name text NOT NULL,
    author text DEFAULT ''::text NOT NULL,
    severity text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    upstream_ref text,
    revision integer DEFAULT 1 NOT NULL,
    availability text DEFAULT 'active'::text NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT templates_availability_check CHECK ((availability = ANY (ARRAY['active'::text, 'unavailable'::text]))),
    CONSTRAINT templates_revision_check CHECK ((revision > 0)),
    CONSTRAINT templates_source_check CHECK ((source = ANY (ARRAY['upstream'::text, 'custom'::text])))
);

CREATE TABLE users (
    id uuid NOT NULL,
    subject text NOT NULL,
    email text,
    name text,
    roles text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY finding_lifecycle ALTER COLUMN id SET DEFAULT nextval('finding_lifecycle_id_seq'::regclass);

ALTER TABLE ONLY findings ALTER COLUMN id SET DEFAULT nextval('findings_id_seq'::regclass);

ALTER TABLE ONLY app_settings
    ADD CONSTRAINT app_settings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY auth_flows
    ADD CONSTRAINT auth_flows_pkey PRIMARY KEY (state);

ALTER TABLE ONLY finding_lifecycle
    ADD CONSTRAINT finding_lifecycle_dedup_key_key UNIQUE (dedup_key);

ALTER TABLE ONLY finding_lifecycle
    ADD CONSTRAINT finding_lifecycle_pkey PRIMARY KEY (id);

ALTER TABLE ONLY findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY scan_policies
    ADD CONSTRAINT scan_policies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY scanner_nodes
    ADD CONSTRAINT scanner_nodes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY scans
    ADD CONSTRAINT scans_id_target_key UNIQUE (id, target_id);

ALTER TABLE ONLY scans
    ADD CONSTRAINT scans_pkey PRIMARY KEY (id);

ALTER TABLE ONLY schedules
    ADD CONSTRAINT schedules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY service_accounts
    ADD CONSTRAINT service_accounts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY targets
    ADD CONSTRAINT targets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY template_set_exclusions
    ADD CONSTRAINT template_set_exclusions_pkey PRIMARY KEY (template_set_id, template_id);

ALTER TABLE ONLY template_set_members
    ADD CONSTRAINT template_set_members_pkey PRIMARY KEY (template_set_id, template_id);

ALTER TABLE ONLY template_sets
    ADD CONSTRAINT template_sets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY template_sync_runs
    ADD CONSTRAINT template_sync_runs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY templates
    ADD CONSTRAINT templates_pkey PRIMARY KEY (id);

ALTER TABLE ONLY templates
    ADD CONSTRAINT templates_source_path_key UNIQUE (source, path) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

CREATE INDEX finding_lifecycle_cve_idx ON finding_lifecycle USING gin (cve);

CREATE INDEX finding_lifecycle_disposition_idx ON finding_lifecycle USING btree (disposition);

CREATE INDEX finding_lifecycle_first_seen_idx ON finding_lifecycle USING btree (first_seen_scan);

CREATE INDEX finding_lifecycle_last_covering_scan_idx ON finding_lifecycle USING btree (last_covering_scan) WHERE (last_covering_scan IS NOT NULL);

CREATE INDEX finding_lifecycle_last_seen_idx ON finding_lifecycle USING btree (last_seen_scan);

CREATE INDEX finding_lifecycle_severity_idx ON finding_lifecycle USING btree (severity);

CREATE INDEX finding_lifecycle_tags_idx ON finding_lifecycle USING gin (tags);

CREATE INDEX finding_lifecycle_template_endpoint_idx ON finding_lifecycle USING btree (template_id, endpoint_key) WHERE (endpoint_key <> ''::text);

CREATE INDEX finding_lifecycle_template_idx ON finding_lifecycle USING btree (template_id);

CREATE INDEX findings_cve_idx ON findings USING gin (cve);

CREATE INDEX findings_dedup_idx ON findings USING btree (dedup_key);

CREATE INDEX findings_finding_id_idx ON findings USING btree (finding_id);

CREATE INDEX findings_finding_target_idx ON findings USING btree (finding_id, target_id);

CREATE INDEX findings_scan_idx ON findings USING btree (scan_id);

CREATE INDEX findings_severity_idx ON findings USING btree (severity);

CREATE INDEX findings_tags_idx ON findings USING gin (tags);

CREATE INDEX findings_target_idx ON findings USING btree (target_id);

CREATE UNIQUE INDEX scan_policies_name_key ON scan_policies USING btree (lower(name));

CREATE UNIQUE INDEX scanner_nodes_name_key ON scanner_nodes USING btree (name);

CREATE INDEX scans_complete_target_created_idx ON scans USING btree (target_id, created_at) WHERE (state = 'complete'::text);

CREATE INDEX schedules_due_idx ON schedules USING btree (next_run_at) WHERE enabled;

CREATE UNIQUE INDEX schedules_name_key ON schedules USING btree (lower(name));

CREATE INDEX schedules_target_id_idx ON schedules USING btree (target_id);

CREATE UNIQUE INDEX service_accounts_name_key ON service_accounts USING btree (name);

CREATE UNIQUE INDEX service_accounts_token_hash_key ON service_accounts USING btree (token_hash);

CREATE INDEX sessions_expires_at_idx ON sessions USING btree (expires_at);

CREATE UNIQUE INDEX targets_name_key ON targets USING btree (lower(name));

CREATE INDEX template_set_exclusions_template_idx ON template_set_exclusions USING btree (template_id);

CREATE INDEX template_set_members_template_idx ON template_set_members USING btree (template_id);

CREATE UNIQUE INDEX template_sets_name_key ON template_sets USING btree (lower(name));

CREATE INDEX template_sync_runs_started_at_idx ON template_sync_runs USING btree (started_at DESC);

CREATE INDEX templates_active_name_idx ON templates USING btree (availability, lower(name));

CREATE INDEX templates_severity_idx ON templates USING btree (severity);

CREATE INDEX templates_source_idx ON templates USING btree (source);

CREATE INDEX templates_tags_gin_idx ON templates USING gin (tags);

CREATE UNIQUE INDEX users_subject_key ON users USING btree (subject);

ALTER TABLE ONLY finding_lifecycle
    ADD CONSTRAINT finding_lifecycle_first_seen_scan_fkey FOREIGN KEY (first_seen_scan) REFERENCES scans(id) ON DELETE SET NULL;

ALTER TABLE ONLY finding_lifecycle
    ADD CONSTRAINT finding_lifecycle_last_covering_scan_fkey FOREIGN KEY (last_covering_scan) REFERENCES scans(id) ON DELETE SET NULL;

ALTER TABLE ONLY finding_lifecycle
    ADD CONSTRAINT finding_lifecycle_last_seen_scan_fkey FOREIGN KEY (last_seen_scan) REFERENCES scans(id) ON DELETE SET NULL;

ALTER TABLE ONLY finding_lifecycle
    ADD CONSTRAINT finding_lifecycle_latest_occurrence_id_fkey FOREIGN KEY (latest_occurrence_id) REFERENCES findings(id) ON DELETE SET NULL;

ALTER TABLE ONLY findings
    ADD CONSTRAINT findings_finding_id_fkey FOREIGN KEY (finding_id) REFERENCES finding_lifecycle(id) ON DELETE SET NULL;

ALTER TABLE ONLY findings
    ADD CONSTRAINT findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE;

ALTER TABLE ONLY findings
    ADD CONSTRAINT findings_scan_scope_fk FOREIGN KEY (scan_id, target_id) REFERENCES scans(id, target_id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY scan_policies
    ADD CONSTRAINT scan_policies_template_set_id_fkey FOREIGN KEY (template_set_id) REFERENCES template_sets(id) ON DELETE RESTRICT;

ALTER TABLE ONLY scans
    ADD CONSTRAINT scans_node_id_fkey FOREIGN KEY (node_id) REFERENCES scanner_nodes(id) ON DELETE SET NULL;

ALTER TABLE ONLY scans
    ADD CONSTRAINT scans_scan_policy_id_fkey FOREIGN KEY (scan_policy_id) REFERENCES scan_policies(id) ON DELETE SET NULL;

ALTER TABLE ONLY scans
    ADD CONSTRAINT scans_schedule_id_fkey FOREIGN KEY (schedule_id) REFERENCES schedules(id) ON DELETE SET NULL;

ALTER TABLE ONLY scans
    ADD CONSTRAINT scans_target_id_fkey FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL;

ALTER TABLE ONLY scans
    ADD CONSTRAINT scans_template_set_id_fkey FOREIGN KEY (template_set_id) REFERENCES template_sets(id) ON DELETE SET NULL;

ALTER TABLE ONLY schedules
    ADD CONSTRAINT schedules_last_scan_id_fkey FOREIGN KEY (last_scan_id) REFERENCES scans(id) ON DELETE SET NULL;

ALTER TABLE ONLY schedules
    ADD CONSTRAINT schedules_scan_policy_id_fkey FOREIGN KEY (scan_policy_id) REFERENCES scan_policies(id) ON DELETE CASCADE;

ALTER TABLE ONLY schedules
    ADD CONSTRAINT schedules_target_id_fkey FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE;

ALTER TABLE ONLY template_set_exclusions
    ADD CONSTRAINT template_set_exclusions_template_id_fkey FOREIGN KEY (template_id) REFERENCES templates(id) ON DELETE RESTRICT;

ALTER TABLE ONLY template_set_exclusions
    ADD CONSTRAINT template_set_exclusions_template_set_id_fkey FOREIGN KEY (template_set_id) REFERENCES template_sets(id) ON DELETE CASCADE;

ALTER TABLE ONLY template_set_members
    ADD CONSTRAINT template_set_members_template_id_fkey FOREIGN KEY (template_id) REFERENCES templates(id) ON DELETE CASCADE;

ALTER TABLE ONLY template_set_members
    ADD CONSTRAINT template_set_members_template_set_id_fkey FOREIGN KEY (template_set_id) REFERENCES template_sets(id) ON DELETE CASCADE;

-- Seed the singleton settings row so reads never special-case an empty table.
INSERT INTO app_settings (id) VALUES (true);

-- 0014 tenant_create() (DATAMODEL §4.1, §7 migration 4; W0-12 "seeds load through
-- tenant_create()"). One transaction: tenant row, genesis audit row, DEKs v1 for payload,
-- credential and config, the two system redaction profiles, alert_rule seed copies (R18) and
-- the active seed scoring_config. Never writes capture_policy (onboarding does, D12).

-- System redaction profiles, copied per tenant with origin='system' (DATAMODEL U5).
CREATE FUNCTION sibyl.system_redaction_detectors(p_name text) RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_agg(jsonb_build_object('id', d, 'params', '{}'::jsonb) ORDER BY ord)
  FROM unnest(sibyl.secrets_baseline_detector_ids()
              || CASE WHEN p_name = 'pii_standard'
                      THEN ARRAY['email', 'phone', 'credit_card', 'iban', 'ip_address', 'national_id', 'postal_address']
                      ELSE ARRAY[]::text[] END) WITH ORDINALITY AS u(d, ord)
$$;

CREATE FUNCTION sibyl.tenant_create(
  p_slug text, p_name text, p_unknown_agent_fail_mode text, p_region_declared text,
  p_kek_id text, p_payload_dek bytea, p_credential_dek bytea, p_config_dek bytea,
  p_request_id uuid DEFAULT NULL, p_tenant_id uuid DEFAULT NULL
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = sibyl, pg_temp AS $$
DECLARE
  v_tenant uuid := coalesce(p_tenant_id, sibyl.uuidv7());
  v_key uuid;
  v_purpose text;
  v_dek bytea;
  v_profile text;
  v_detectors jsonb;
  v_canonical text;
  v_seed record;
  v_rule jsonb;
BEGIN
  IF p_payload_dek IS NULL OR p_credential_dek IS NULL OR p_config_dek IS NULL OR coalesce(p_kek_id, '') = '' THEN
    RAISE EXCEPTION 'sibyl:tenant_create_invalid: tenant_create needs three wrapped DEKs and a KEK id' USING ERRCODE = 'SB049';
  END IF;
  INSERT INTO sibyl.tenant (id, slug, name, unknown_agent_fail_mode, region_declared)
  VALUES (v_tenant, p_slug, p_name, p_unknown_agent_fail_mode, p_region_declared);
  PERFORM set_config('app.tenant_id', v_tenant::text, true);

  PERFORM sibyl.audit_append(v_tenant, 'system', NULL, NULL, NULL, 'audit.genesis', 'tenant', v_tenant, p_slug, NULL,
    jsonb_build_object('chain_version', 1), NULL, now(), p_request_id);
  PERFORM sibyl.pseudonym_key_create(v_tenant);

  FOREACH v_purpose IN ARRAY ARRAY['payload', 'credential', 'config'] LOOP
    v_dek := CASE v_purpose WHEN 'payload' THEN p_payload_dek WHEN 'credential' THEN p_credential_dek
                            ELSE p_config_dek END;
    INSERT INTO sibyl.tenant_key (tenant_id, purpose, version, wrapped_dek, kek_id)
    VALUES (v_tenant, v_purpose, 1, v_dek, p_kek_id) RETURNING id INTO v_key;
    PERFORM sibyl.audit_append(v_tenant, 'system', NULL, NULL, NULL, 'tenant_key.created', 'tenant_key', v_key,
      v_purpose || ':v1', NULL,
      jsonb_build_object('key_id', v_key, 'purpose', v_purpose, 'version', 1, 'kek_id', p_kek_id),
      NULL, now(), p_request_id);
  END LOOP;

  FOREACH v_profile IN ARRAY ARRAY['secrets_only', 'pii_standard'] LOOP
    v_detectors := sibyl.system_redaction_detectors(v_profile);
    v_canonical := sibyl.jcs(jsonb_build_object('detectors', v_detectors, 'replacement_format', '[{kind}:{hash8}]'));
    INSERT INTO sibyl.redaction_profile (tenant_id, name, version_no, origin, detectors, content_canonical,
                                         content_hash)
    VALUES (v_tenant, v_profile, 1, 'system', v_detectors, v_canonical, sibyl.sha256_text(v_canonical));
  END LOOP;

  SELECT * INTO v_seed FROM sibyl.rules_seed();
  FOR v_rule IN SELECT r FROM jsonb_array_elements(v_seed.rules) AS r LOOP
    INSERT INTO sibyl.alert_rule (tenant_id, code, short_code, kind, scope, metric, comparator, thresholds, window_s,
      min_samples, trend_windows, hysteresis_in, hysteresis_out, cooldown_s, severity, penalty, horizon_s,
      tier_applicability, collapses_to_provider, what_to_do_template, origin, seed_version, yaml_sha256)
    VALUES (v_tenant, v_rule->>'code', v_rule->>'short_code', v_rule->>'kind', v_rule->>'scope', v_rule->>'metric',
      v_rule->>'comparator', v_rule->'thresholds', (v_rule->>'window_s')::integer,
      (v_rule->>'min_samples')::integer, (v_rule->>'trend_windows')::smallint,
      (v_rule->>'hysteresis_in')::smallint, (v_rule->>'hysteresis_out')::smallint,
      (v_rule->>'cooldown_s')::integer, v_rule->>'severity', (v_rule->>'penalty')::smallint,
      (v_rule->>'horizon_s')::integer,
      ARRAY(SELECT jsonb_array_elements_text(v_rule->'tier_applicability')::smallint),
      (v_rule->>'collapses_to_provider')::boolean, v_rule->>'what_to_do', 'seed', v_seed.seed_version,
      v_seed.yaml_sha256);
  END LOOP;

  INSERT INTO sibyl.scoring_config (tenant_id, rules_source, feature_set, version_no, config, config_canonical,
                                    config_sha256, origin, activated_at)
  VALUES (v_tenant, v_seed.rules_source, v_seed.feature_set, 1, v_seed.scoring_canonical::jsonb,
          v_seed.scoring_canonical, sibyl.sha256_text(v_seed.scoring_canonical), 'seed', now());

  PERFORM sibyl.audit_append(v_tenant, 'system', NULL, NULL, NULL, 'tenant.created', 'tenant', v_tenant, p_slug, NULL,
    jsonb_build_object('slug', p_slug, 'residency_region', p_region_declared), NULL, now(), p_request_id);
  RETURN v_tenant;
END
$$;

GRANT EXECUTE ON FUNCTION sibyl.tenant_create(text, text, text, text, text, bytea, bytea, bytea, uuid, uuid)
  TO sibyl_app;
GRANT EXECUTE ON FUNCTION sibyl.system_redaction_detectors(text) TO sibyl_app, sibyl_worker;

-- Change request for INT-1 (lane P, wave 2): silences on alerts (API.md §5.9 `silence`,
-- OpenAPI Alert.silenced_until; ML.md §3.7 "silenced and expired while breaching re-opens").
-- Tests apply this after the real migrations until INT-1 lands it as a migration.
ALTER TABLE sibyl.alert ADD COLUMN IF NOT EXISTS silenced_until timestamptz;
ALTER TABLE sibyl.alert ADD COLUMN IF NOT EXISTS silenced_by_user_id uuid;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_alert_silenced_by') THEN
    ALTER TABLE sibyl.alert ADD CONSTRAINT fk_alert_silenced_by FOREIGN KEY (tenant_id, silenced_by_user_id)
      REFERENCES sibyl.app_user (tenant_id, id) DEFERRABLE INITIALLY IMMEDIATE;
  END IF;
END
$$;
CREATE INDEX IF NOT EXISTS ix_alert_silenced ON sibyl.alert (tenant_id, silenced_until)
  WHERE silenced_until IS NOT NULL;

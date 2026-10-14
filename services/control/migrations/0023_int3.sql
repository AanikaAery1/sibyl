-- 0023 lane INT-3: integration fixes carried from wave 2 (docs/council/build/LANES.md B19-B21).
--
-- * B21: `access.break_glass` is attributed to the break-glass key itself (actor `api_key`, key
--   id recorded) when a key pulls a kill switch; `system` stays allowed for the worker. Mirrors
--   sibyl_schemas._audit (the seed drift tests compare the two).
-- (0022 is reserved for the HARNESS lane.)

UPDATE sibyl.audit_action
   SET actor_types = ARRAY['system', 'api_key']::text[]
 WHERE name = 'access.break_glass';

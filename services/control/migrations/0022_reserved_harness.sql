-- 0022 is reserved for the HARNESS lane (wave 3). This placeholder only keeps migration versions
-- contiguous (migrate/runner.py) so INT-3's 0023 can be tested on its own; it changes nothing.
-- At merge: replace it with the HARNESS lane's 0022, or keep it if HARNESS needs no migration.
SELECT 1;

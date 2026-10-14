-- 0015 initial partitions (risk T9b: the partition job runs once at migrate time, then
-- hourly in the worker): one period back to each table's `ahead` window.
SELECT sibyl.partition_ensure_ahead(now());

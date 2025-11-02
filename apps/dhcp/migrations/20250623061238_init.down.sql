-- Add down migration script here
DROP INDEX IF EXISTS idx_ip_pools_zone_id;
DROP INDEX IF EXISTS idx_zone_pcs_pc_uuid;
DROP TABLE IF EXISTS ip_pools;
DROP TABLE IF EXISTS zone_pcs;
DROP TABLE IF EXISTS zones;

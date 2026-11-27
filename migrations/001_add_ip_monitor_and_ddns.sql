-- Migration: Add dual-stack IP change tracking and DDNS configuration columns to servers table
-- Run locally:  npx wrangler d1 execute server-monitor-db --local --file=migrations/001_add_ip_monitor_and_ddns.sql
-- Run remotely: npx wrangler d1 execute server-monitor-db --remote --file=migrations/001_add_ip_monitor_and_ddns.sql

ALTER TABLE servers ADD COLUMN last_ipv4 TEXT DEFAULT '';
ALTER TABLE servers ADD COLUMN last_ipv6 TEXT DEFAULT '';
ALTER TABLE servers ADD COLUMN pending_ip TEXT DEFAULT '';
ALTER TABLE servers ADD COLUMN pending_ip_count INTEGER DEFAULT 0;
ALTER TABLE servers ADD COLUMN ddns_enabled TEXT DEFAULT '0';
ALTER TABLE servers ADD COLUMN ddns_domain TEXT DEFAULT '';
ALTER TABLE servers ADD COLUMN ddns_record_type TEXT DEFAULT 'AUTO';

-- Migration: 002_add_trusted_column.sql
-- Add trusted column to peers and index for quick lookup
BEGIN TRANSACTION;

ALTER TABLE peers ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_peers_trusted ON peers(trusted);

COMMIT;

-- This file should undo anything in `up.sql`
ALTER TABLE "account" DROP COLUMN IF EXISTS "type";

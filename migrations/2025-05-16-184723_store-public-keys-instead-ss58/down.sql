-- This file should undo anything in `up.sql`

ALTER TABLE "address" DROP COLUMN "public_key";
ALTER TABLE "address" ADD COLUMN "address" VARCHAR NOT NULL;

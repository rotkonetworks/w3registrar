-- Replace 'address' column with 'public_key' in 'account' table

ALTER TABLE "address" DROP COLUMN "address";
ALTER TABLE "address" ADD COLUMN "public_key" BYTEA NOT NULL;

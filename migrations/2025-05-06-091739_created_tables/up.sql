-- Your SQL goes here
CREATE TABLE "address" (
	"id" INT4 NOT NULL PRIMARY KEY,
	"address" VARCHAR NOT NULL,
	"network" VARCHAR NOT NULL,
	"created_at" TIMESTAMP NOT NULL DEFAULT NOW(),
	"updated_at" TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE "account" (
	"id" INT4 NOT NULL PRIMARY KEY,
	"address_id" INT4 NOT NULL,
	"name" VARCHAR NOT NULL,
	"varified" BOOLEAN NOT NULL DEFAULT FALSE,
	"created_at" TIMESTAMP NOT NULL DEFAULT NOW(),
	"updated_at" TIMESTAMP NOT NULL DEFAULT NOW()
);

ALTER TABLE "account" ADD CONSTRAINT "fk_address_account" FOREIGN KEY ("address_id") REFERENCES "address"("id") ON DELETE CASCADE;


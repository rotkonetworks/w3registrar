-- Your SQL goes here
CREATE TABLE "account"(
	"id" INT4 NOT NULL PRIMARY KEY,
	"address" VARCHAR NOT NULL,
	"network" VARCHAR NOT NULL
);

CREATE TABLE "challenge"(
	"id" INT4 NOT NULL PRIMARY KEY,
	"account_id" INT4 NOT NULL,
	"secret" VARCHAR NOT NULL,
	"created_at" TIMESTAMP NOT NULL
);

ALTER TABLE "challenge" ADD CONSTRAINT "fk_challenge_account" FOREIGN KEY ("account_id") REFERENCES "account"("id") ON DELETE CASCADE;


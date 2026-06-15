CREATE TYPE "public"."approval_status" AS ENUM('pending', 'approved', 'denied');--> statement-breakpoint
CREATE TYPE "public"."audit_action" AS ENUM('principal.register', 'principal.login', 'principal.logout', 'passport.create', 'credential.deposit', 'credential.use', 'credential.proxy', 'agent.issue', 'agent.revoke', 'agent.mtls_bind', 'approval.approve', 'approval.deny', 'oauth.start', 'oauth.capture', 'auth.denied', 'authz.denied');--> statement-breakpoint
CREATE TYPE "public"."credential_type" AS ENUM('password', 'oauth_token', 'cookie', 'api_key');--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "agents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"passport_id" uuid NOT NULL,
	"name" text NOT NULL,
	"secret_hash" text NOT NULL,
	"cert_fingerprint" text,
	"scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"revoked_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "approval_requests" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"credential_id" uuid NOT NULL,
	"passport_id" uuid NOT NULL,
	"agent_id" uuid NOT NULL,
	"status" "approval_status" DEFAULT 'pending' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"decided_at" timestamp with time zone,
	"decided_by" uuid,
	"consumed_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "audit_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"seq" bigserial NOT NULL,
	"action" "audit_action" NOT NULL,
	"principal_id" uuid,
	"passport_id" uuid,
	"agent_id" uuid,
	"credential_id" uuid,
	"success" boolean NOT NULL,
	"detail" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"ip" text,
	"prev_hash" text,
	"hash" text NOT NULL,
	"hash_key_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "audit_events_seq_unique" UNIQUE("seq")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"passport_id" uuid NOT NULL,
	"target" text NOT NULL,
	"label" text NOT NULL,
	"type" "credential_type" NOT NULL,
	"sealed" jsonb NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"injection" jsonb,
	"expires_at" timestamp with time zone,
	"max_uses" integer,
	"use_count" integer DEFAULT 0 NOT NULL,
	"allowed_from" timestamp with time zone,
	"allowed_until" timestamp with time zone,
	"require_approval" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "oauth_flows" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"state" text NOT NULL,
	"code_verifier" text NOT NULL,
	"principal_id" uuid NOT NULL,
	"passport_id" uuid NOT NULL,
	"provider" text NOT NULL,
	"target" text NOT NULL,
	"label" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "oauth_flows_state_unique" UNIQUE("state")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "passports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"principal_id" uuid NOT NULL,
	"name" text NOT NULL,
	"wrapped_dek" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "principals" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"password_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "principals_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "revoked_sessions" (
	"jti" text PRIMARY KEY NOT NULL,
	"principal_id" uuid,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "agents" ADD CONSTRAINT "agents_passport_id_passports_id_fk" FOREIGN KEY ("passport_id") REFERENCES "public"."passports"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "approval_requests" ADD CONSTRAINT "approval_requests_credential_id_credentials_id_fk" FOREIGN KEY ("credential_id") REFERENCES "public"."credentials"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "approval_requests" ADD CONSTRAINT "approval_requests_passport_id_passports_id_fk" FOREIGN KEY ("passport_id") REFERENCES "public"."passports"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "approval_requests" ADD CONSTRAINT "approval_requests_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "credentials" ADD CONSTRAINT "credentials_passport_id_passports_id_fk" FOREIGN KEY ("passport_id") REFERENCES "public"."passports"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "passports" ADD CONSTRAINT "passports_principal_id_principals_id_fk" FOREIGN KEY ("principal_id") REFERENCES "public"."principals"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "agents_passport_idx" ON "agents" USING btree ("passport_id");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "agents_cert_fingerprint_idx" ON "agents" USING btree ("cert_fingerprint");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "approval_requests_passport_idx" ON "approval_requests" USING btree ("passport_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "approval_requests_cred_agent_status_idx" ON "approval_requests" USING btree ("credential_id","agent_id","status");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_seq_idx" ON "audit_events" USING btree ("seq");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_created_idx" ON "audit_events" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_passport_idx" ON "audit_events" USING btree ("passport_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_principal_idx" ON "audit_events" USING btree ("principal_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_agent_idx" ON "audit_events" USING btree ("agent_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "credentials_passport_idx" ON "credentials" USING btree ("passport_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "oauth_flows_state_idx" ON "oauth_flows" USING btree ("state");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "passports_principal_idx" ON "passports" USING btree ("principal_id");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "revoked_sessions_expiry_idx" ON "revoked_sessions" USING btree ("expires_at");
CREATE TYPE "public"."mfa_status" AS ENUM('pending', 'approved', 'denied', 'consumed', 'expired', 'revoked');--> statement-breakpoint
ALTER TYPE "public"."audit_action" ADD VALUE IF NOT EXISTS 'mfa.requested' BEFORE 'auth.denied';--> statement-breakpoint
ALTER TYPE "public"."audit_action" ADD VALUE IF NOT EXISTS 'mfa.approved' BEFORE 'auth.denied';--> statement-breakpoint
ALTER TYPE "public"."audit_action" ADD VALUE IF NOT EXISTS 'mfa.consumed' BEFORE 'auth.denied';--> statement-breakpoint
ALTER TYPE "public"."audit_action" ADD VALUE IF NOT EXISTS 'mfa.denied' BEFORE 'auth.denied';--> statement-breakpoint
ALTER TYPE "public"."audit_action" ADD VALUE IF NOT EXISTS 'mfa.expired' BEFORE 'auth.denied';--> statement-breakpoint
ALTER TYPE "public"."audit_action" ADD VALUE IF NOT EXISTS 'mfa.revoked' BEFORE 'auth.denied';--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "mfa_requests" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"challenge_id" text NOT NULL,
	"credential_id" uuid NOT NULL,
	"passport_id" uuid NOT NULL,
	"agent_id" uuid NOT NULL,
	"principal_id" uuid NOT NULL,
	"status" "mfa_status" DEFAULT 'pending' NOT NULL,
	"kind" text NOT NULL,
	"channel_hint" text,
	"prompt_text" text,
	"sealed_code" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"decided_at" timestamp with time zone,
	"decided_by" uuid,
	"consumed_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "mfa_requests" ADD CONSTRAINT "mfa_requests_credential_id_credentials_id_fk" FOREIGN KEY ("credential_id") REFERENCES "public"."credentials"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "mfa_requests" ADD CONSTRAINT "mfa_requests_passport_id_passports_id_fk" FOREIGN KEY ("passport_id") REFERENCES "public"."passports"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "mfa_requests" ADD CONSTRAINT "mfa_requests_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "mfa_requests_agent_status_idx" ON "mfa_requests" USING btree ("agent_id","status");--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "mfa_requests_passport_idx" ON "mfa_requests" USING btree ("passport_id");
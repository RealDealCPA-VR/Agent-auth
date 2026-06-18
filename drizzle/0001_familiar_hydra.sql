ALTER TYPE "public"."audit_action" ADD VALUE IF NOT EXISTS 'credential.proxy' BEFORE 'agent.issue';--> statement-breakpoint
ALTER TABLE "credentials" ADD COLUMN IF NOT EXISTS "injection" jsonb;

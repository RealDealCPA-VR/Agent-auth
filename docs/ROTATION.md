# Key Rotation Runbook

AgentAuth uses three independent keys, each versioned so it can be rotated with no
downtime and no loss of access to existing data. All three follow the same shape:
an **active** key with an id, plus a set of **retired** keys kept only long enough
for old data/tokens to age out.

| Key              | Wraps / signs                 | Active env                                                          | Retired env           | Per-record id               |
| ---------------- | ----------------------------- | ------------------------------------------------------------------- | --------------------- | --------------------------- |
| **KEK** (master) | per-passport data keys (DEKs) | `MASTER_KEY` + `MASTER_KEY_ID`                                      | `MASTER_KEYS_RETIRED` | `passports.wrapped_dek.kid` |
| **JWT**          | human session tokens          | `JWT_SECRET` + `JWT_KEY_ID`                                         | `JWT_SECRETS_RETIRED` | token header `kid`          |
| **Audit HMAC**   | audit hash-chain              | `AUDIT_HMAC_SECRET` (or derived from `MASTER_KEY`) + `AUDIT_KEY_ID` | `AUDIT_KEYS_RETIRED`  | `audit_events.hash_key_id`  |

`*_RETIRED` values are JSON objects mapping `kid -> base64-of-32-bytes`, e.g.
`{"k1":"<old-base64-32B>"}`. They are validated at boot; a malformed value fails
fast with a clear message.

Generate a fresh 32-byte key:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

---

## 1. Rotating the master KEK (`MASTER_KEY`)

The KEK only wraps DEKs; rotating it re-wraps each passport's DEK without touching
the DEK itself, so every sealed credential stays decryptable throughout.

1. Generate a new key and choose a new id (e.g. `k2`).
2. Deploy with the new key **active** and the old key **retired**:
   ```bash
   MASTER_KEY=<new-base64>      \
   MASTER_KEY_ID=k2             \
   MASTER_KEYS_RETIRED='{"k1":"<old-base64>"}'
   ```
   At this point new passports use `k2`; existing passports still carry `k1`-wrapped
   DEKs, which remain readable because `k1` is in `MASTER_KEYS_RETIRED`.
3. Re-wrap all existing passports under the active key:
   ```bash
   pnpm db:rotate
   ```
   This is idempotent — passports already on the active key are skipped — and prints
   `rotated N/total passport keys to active KEK "k2"`.
4. Once `pnpm db:rotate` reports `0` remaining on the old key, remove the retired
   entry on the next deploy (`MASTER_KEYS_RETIRED` empty) — **but see the audit-chain
   note below before dropping it.**

> Losing `MASTER_KEY` with no retired copy makes all DEKs (and therefore all
> credentials) unrecoverable. Back the KEK up in a secret manager — or use the KMS
> provider (below) so the KEK never lives in app config at all.

> **Audit chain & the KEK.** When `AUDIT_HMAC_SECRET` is unset (the default), the
> audit hash-chain key is derived from `MASTER_KEY`. The chain is kept verifiable
> across a KEK rotation **automatically**: each master version signs audit rows
> under a distinct key id (`<AUDIT_KEY_ID>~<MASTER_KEY_ID>`), and the server derives
> the audit key for every entry still listed in `MASTER_KEYS_RETIRED`. So keep a
> rotated-out master in `MASTER_KEYS_RETIRED` for **as long as you retain audit
> history signed under it** — dropping it (step 4) makes rows signed under that
> master fail `GET /v1/audit/verify`. To decouple the audit chain from the KEK
> entirely, set an explicit `AUDIT_HMAC_SECRET` (section 3); then `MASTER_KEY`
> rotation never affects audit verification. (One caveat: audit rows written by a
> build **before** key-id qualification carry the bare `AUDIT_KEY_ID`; set an
> explicit `AUDIT_HMAC_SECRET` before your first KEK rotation if you must keep that
> pre-existing history verifiable.)

### KMS-backed KEK (no master key in app memory)

Set `KEY_PROVIDER=kms`, `KMS_KEY_ID=<arn|alias>`, `KMS_REGION`, and install the
optional dependency `@aws-sdk/client-kms`. Rotation is then handled by the KMS key
policy; `pnpm db:rotate` still re-wraps DEKs to the current `KMS_KEY_ID` if you
move to a new KMS key.

## 2. Rotating the JWT signing key

Tokens carry the signing key's `kid` in their header, and verification resolves the
key by `kid`, so a roll never invalidates already-issued sessions.

1. Generate a new key, choose a new id (e.g. `j2`).
2. Deploy:
   ```bash
   JWT_SECRET=<new-base64>      \
   JWT_KEY_ID=j2               \
   JWT_SECRETS_RETIRED='{"j1":"<old-base64>"}'
   ```
   New tokens are signed with `j2`; tokens signed with `j1` keep verifying until
   they expire (`JWT_TTL_SECONDS`, default 1h).
3. After `JWT_TTL_SECONDS` has elapsed, drop the retired entry on the next deploy.

## 3. Rotating the audit HMAC key

Each audit row records the `hash_key_id` that signed it, and chain verification
selects the key per row, so old rows keep verifying after a roll.

1. Generate a new key, choose a new id (e.g. `a2`). Capture the **current active
   key's bytes** before rotating so you can retire it, and note **the key id your
   existing rows were signed under** (this is what you retire it as):
   - If `AUDIT_HMAC_SECRET` was already set, the stored kid is the bare
     `AUDIT_KEY_ID` (e.g. `a1`); retire under that.
   - If it was unset (derived mode — the default), the audit key was derived from
     `MASTER_KEY` and rows were signed under the **master-qualified** kid
     `<AUDIT_KEY_ID>~<MASTER_KEY_ID>` (e.g. `a1~k1`). Retire under that exact kid,
     and the bytes are `HMAC-SHA256(base64-decode(MASTER_KEY), 'agentauth-audit-chain-v1')`,
     not the raw `MASTER_KEY`.
2. Deploy (example for a derived-mode install whose rows are signed `a1~k1`):
   ```bash
   AUDIT_HMAC_SECRET=<new-base64>            \
   AUDIT_KEY_ID=a2                          \
   AUDIT_KEYS_RETIRED='{"a1~k1":"<old-derived-base64>"}'
   ```
   New rows are signed with `a2`; `GET /v1/audit/verify` still validates older rows
   under their original kid. Audit rows are append-only and permanent, so **keep
   retired audit keys for as long as you retain audit history.** (Retiring under the
   wrong kid — e.g. bare `a1` for a derived install — makes verify report the whole
   history as tampered.)

---

## Scheduling rotation (KEK re-wrap)

The re-wrap is safe to run on a schedule. **In the shipped Docker image run the
compiled entrypoint `node dist/db/rotate-keys.js`** — the runtime image has no
`pnpm`/`tsx`/`src` (those are build-time only), so `pnpm db:rotate` is for local
dev only and would fail in-container. This mirrors how migrations run in
`docker-compose.yml` (`node dist/db/migrate.js`). Example Kubernetes CronJob that
re-wraps DEKs nightly (env injected from your secret store):

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: agentauth-key-rotate
spec:
  schedule: '17 3 * * *' # 03:17 daily
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: rotate
              image: agentauth:latest
              command: ['node', 'dist/db/rotate-keys.js']
              envFrom:
                - secretRef:
                    name: agentauth-secrets
```

systemd timer equivalent: a `agentauth-rotate.service` running
`node dist/db/rotate-keys.js` (with the env file) plus an `agentauth-rotate.timer`
on `OnCalendar=*-*-* 03:17:00`.

The actual key _material_ roll (steps 1–2 above) is a deploy-time action — change
the env, ship, then let the scheduled `db:rotate` converge existing data.

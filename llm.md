# Jaybase agent guide

Use this document as the operating contract for an agent that reads or writes
Jaybase. For deployment and human administration, use `README.md` and `docs/`.

## What Jaybase is

Jaybase is an authenticated, append-only event store for durable business facts.
It records who asserted something, when it was asserted, the command that caused
the assertion, and an encrypted JSON payload. Its hash-linked history is the
source of truth.

Jaybase does not decide whether a fact is true, enforce a domain schema, or
materialize current entity state. The consuming agent must validate evidence,
apply its domain rules, and derive current state by replaying relevant events.

Prefer the hosted HTTP API. Never read or edit Jaybase's `objects/`, `refs/`, or
`keys/` files directly.

## Required connection inputs

- `JAYBASE_URL`: HTTPS origin, without a trailing slash.
- `JAYBASE_TOKEN`: bearer token assigned to this agent.
- Role: `reader`, `writer`, or `admin`. Roles are cumulative.

Never put a token in a URL, payload, log, source file, prompt transcript, or
idempotency key. Send it only in the `Authorization` header. Use the lowest role
that can complete the task.

All `/v1` requests use:

```http
Authorization: Bearer <token>
```

Requests with JSON bodies also use:

```http
Content-Type: application/json
```

## Read workflow

1. Confirm availability with `GET /health/ready`. This route needs no token and
   discloses no facts.
2. Fetch `GET /v1/root` and retain the returned root for any dependent write.
3. Read events with `GET /v1/events?limit=100`.
4. Payloads are omitted by default. Add `include_payload=true` only when the task
   requires decrypted content.
5. If `has_more` is true, take the final event's `hash` and request the next page
   with `after=<hash>`. Continue until `has_more` is false.

Example:

```sh
curl -fsS \
  -H "Authorization: Bearer $JAYBASE_TOKEN" \
  "$JAYBASE_URL/v1/events?after=$LAST_HASH&limit=100&include_payload=true"
```

Do not treat the last event for an entity as current state unless the domain's
replay rules say that is correct. Corrections, retractions, approvals, and
superseding assertions may all change how earlier events are interpreted.

## Write workflow

Every append requires both optimistic concurrency and retry identity:

- `expected_root`: the exact value from the most recent `GET /v1/root`. Use `""`
  only when the database is empty.
- `Idempotency-Key`: a stable identifier for one logical operation, 8-200
  characters. Prefer an immutable upstream operation ID or a UUID stored before
  the first attempt. Never generate a new key merely because a request timed out.

Example:

```sh
curl -fsS -X POST "$JAYBASE_URL/v1/events" \
  -H "Authorization: Bearer $JAYBASE_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: crm-sync-contact-42-v7" \
  --data '{
    "type": "business.fact",
    "entity_id": "customer:42",
    "command": "fact assert",
    "payload": {
      "predicate": "primary_contact",
      "value": "Ada Lovelace",
      "observed_at": "2026-07-17T20:00:00Z",
      "evidence": {"kind": "crm_record", "ref": "contact:42"}
    },
    "expected_root": "sha256:..."
  }'
```

The server derives `actor`, `role`, `created_at`, parents, encryption fields, and
hash. Do not include or attempt to override them.

Interpret a successful response as follows:

- `201` and `replayed: false`: a new event was committed.
- `200` and `replayed: true`: this exact logical request was already committed;
  treat it as success and use the returned hash.
- `root`: the current database root after the request. It may be newer than
  `hash` when an old successful request is replayed.

## Conflict and retry algorithm

On a timeout, connection loss, or unknown result:

1. Retry the exact same body with the exact same `Idempotency-Key`.
2. If the first request committed, Jaybase returns the original hash with
   `replayed: true`.
3. If it did not commit, the retry can commit normally if the expected root is
   still current.

On `409 conflict` with a root-changed message:

1. Fetch the current root and events after the root on which the decision was
   based.
2. Re-evaluate the operation against those intervening facts.
3. If the operation is still valid, submit it against the new root. It is safe to
   retain the idempotency key when the stale request was definitively rejected.
4. If the operation is no longer valid, do not append it. Report the conflict to
   the caller with the facts that changed the decision.

On `409 conflict` saying the request ID was used for different content, stop.
This is a client bug or an idempotency-key collision. Never resolve it by silently
inventing a new key.

Never blindly loop on `409`. Concurrency conflicts require domain reconciliation.

## Fact modeling conventions

Jaybase accepts arbitrary JSON, but agents should keep a stable contract:

- `type`: namespaced event category with stable semantics, such as
  `business.fact`, `crm.customer.updated`, or `policy.approved`.
- `entity_id`: stable domain identifier, not a display name.
- `command`: concise intent that produced the event, such as `fact assert`,
  `fact correct`, or `policy approve`.
- `payload`: the assertion plus the evidence needed to independently understand
  it. Prefer references to authoritative sources over unsupported prose.

When useful, include these payload fields:

- `predicate` and `value` for an asserted fact;
- `observed_at` for the source observation time;
- `evidence` with a source kind and durable reference;
- `confidence` only when uncertainty is meaningful and its scale is defined;
- `supersedes` or `retracts` containing a prior Jaybase hash;
- `reason` for corrections, retractions, and approvals.

Never mutate an earlier event. To correct or retract a fact, append a new event
that references the old hash and explains the change. Preserve the evidence that
led to both states.

Do not store plaintext secrets merely because Jaybase encrypts payloads. Store a
secret-manager reference when possible. Event metadata—type, entity ID, actor,
role, command, time, and graph shape—is not encrypted.

## Named refs

Named refs are durable checkpoints, not mutable facts.

- Read: `GET /v1/refs/{name}`.
- Write: `PUT /v1/refs/{name}` with `{"root":"sha256:..."}`.

Use simple file-safe names. The root must already exist. A ref does not create a
branch or freeze the current database root.

## Error handling

Errors have this structure:

```json
{"error":{"code":"conflict","message":"root changed"}}
```

Handle codes deliberately:

- `validation_error`: fix the request; do not retry unchanged.
- `permission_denied`: stop and obtain the correct least-privilege credential.
- `not_found`: refresh the root, cursor, or named-ref assumption.
- `conflict`: follow the conflict algorithm above.
- `internal_error`: retry the identical idempotent request with bounded backoff;
  alert an operator if it persists.

Also expect HTTP `401` for a missing or invalid token, `403` for insufficient
role, and `415` for a non-JSON body. Request bodies are limited to 1 MiB.

Use bounded exponential backoff with jitter for transient transport and server
errors. Do not retry validation, authentication, authorization, or semantic
conflicts without changing the underlying condition.

## Administrative operations

Ordinary fact agents should not receive `admin` credentials.

- `POST /v1/admin/verify` walks the reachable history and authenticates every
  encrypted payload.
- `POST /v1/admin/snapshots` writes a consistent encrypted archive that excludes
  the data key.

A successful snapshot on the Jaybase host is not yet a backup. An operator must
copy it off-host and retain the data key in a separate failure domain.

## Non-negotiable invariants

- Use HTTPS except for an explicitly local test.
- Treat the bearer token and decrypted payloads as sensitive.
- Read before making a decision; fetch a root immediately before writing.
- Reuse the same idempotency key and body for an ambiguous retry.
- Reconcile rather than overwrite when the root changes.
- Append corrections; never rewrite history.
- Never operate on Jaybase storage files directly.
- Never run multiple Jaybase server replicas against the same volume.
- Never claim that tamper evidence proves a business assertion is true.

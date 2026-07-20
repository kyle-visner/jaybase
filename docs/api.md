# HTTP API

All responses are JSON. Routes under `/v1` require
`Authorization: Bearer <token>`. Error responses have this shape:

```json
{"error":{"code":"conflict","message":"root changed"}}
```

Roles are cumulative: writers can read; admins can read and write.

## Health

`GET /health/live` reports that the process is running. `GET /health/ready`
verifies that the current root addresses a valid, complete head node in constant
time. Neither route exposes data or requires authentication; the admin verify
route performs the full history and decryption check. A failed readiness check
returns `503` with `status: "not_ready"` and an `integrity_error`.

## Root

`GET /v1/root` requires `reader` and returns:

```json
{"root":"sha256:..."}
```

The root is an empty string for a new database.

## Append event

`POST /v1/events` requires `writer`, `Content-Type: application/json`, and an
`Idempotency-Key` of 8-200 characters.

```json
{
  "type": "business.fact",
  "entity_id": "customer:42",
  "command": "fact assert",
  "payload": {"status": "active"},
  "expected_root": "sha256:..."
}
```

`expected_root` is required. Use `""` only for the first event. A successful new
append returns `201`; an identical retry returns `200` with `replayed: true`.
A stale root or reused idempotency key with different content returns `409`.

## Replay events

`GET /v1/events` requires `reader`.

Query parameters:

- `limit`: 1-1000, default 100.
- `after`: return nodes strictly after this hash in the current history.
- `include_payload=true`: decrypt and include payloads. Payloads are omitted by
  default.

The response includes `events`, the current `root`, and `has_more`. The `root`
is the live history tip captured atomically with that page. `has_more` says
whether more events followed the returned page at the time of that request; a
concurrent append can therefore change both values on a later page.

For a concurrency-safe incremental replay:

1. Request the first page after the client's cached root and capture that
   response's `root` as the target replay boundary.
2. Apply events in order. If an event's hash equals the captured target, stop
   immediately; do not apply later events from the same response.
3. Until the target is reached, request another page with the final applied
   event hash as `after`. Later responses may report a newer `root`; keep the
   original target.
4. If the first response has no events and its `root` equals the cached root,
   the client is already caught up. An empty store likewise has an empty target.

Jaybase's history is a linear append-only chain, so the captured target remains
reachable when a concurrent writer advances the live root. A cached `after`
hash that is not in the current history returns structured `404 not_found`; the
client must invalidate that checkpoint and perform a cold replay. This can
happen after restoring or replacing a store. Payload omission and
`include_payload=true` behave identically during bounded replay.

## Named refs

- `GET /v1/refs/{name}` requires `reader`.
- `PUT /v1/refs/{name}` requires `writer` and body
  `{"root":"sha256:new","expected_root":"sha256:old"}`. Use an empty
  `expected_root` only when creating a new ref.

A ref name must be a simple filename. The selected root must name an existing,
valid node. If the current ref differs from `expected_root`, the update returns
`409 conflict` without overwriting it.

## Administration

- `POST /v1/admin/verify` requires `admin`. It verifies every reachable node and
  decrypts every reachable payload.
- `POST /v1/admin/snapshots` requires `admin`. It creates a consistent archive in
  the configured backup volume and returns its filename, root, timestamp, and
  node count. The archive does not include the data key. The endpoint refuses
  the request with `507 capacity_exceeded` if the estimated archive would consume
  the configured free-space reserve and prunes the oldest managed snapshots
  after a successful write. If post-write retention cleanup fails, the durable
  archive still returns `201`; the server logs the cleanup failure for operators.

Request bodies are limited to 1 MiB at the application and 2 MiB at the proxy;
an application-limit violation returns one structured `413 validation_error`.
Stored-data validation, hash, and decryption failures return
`500 integrity_error`, not a client validation error.

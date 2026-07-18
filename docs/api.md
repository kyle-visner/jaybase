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

The response includes `events`, the current `root`, and `has_more`. Continue by
passing the final returned event hash as `after`.

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
  after a successful write.

Request bodies are limited to 1 MiB at the application and 2 MiB at the proxy;
an application-limit violation returns one structured `413 validation_error`.
Stored-data validation, hash, and decryption failures return
`500 integrity_error`, not a client validation error.

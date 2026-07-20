# Jaybase

Jaybase is a hostable, AI-native information base for replayable,
tamper-evident business facts. It stores an append-only chain of encrypted JSON
events and exposes that chain through a small authenticated HTTP API.

The Go module remains usable as an embedded local library. Hosted mode adds the
network, identity, concurrency, backup, and operational boundaries needed for a
shared source of truth.

## Hosted model

- A single Jaybase process owns the writable data volume.
- Caddy terminates HTTPS and obtains certificates automatically.
- Bearer credentials map to `reader`, `writer`, or `admin`; plaintext tokens are
  never stored by Jaybase.
- Every hosted append includes an expected root and idempotency key, making
  concurrent updates explicit and retries safe.
- Payloads use AES-256-GCM at rest. The data key is mounted separately from the
  volume and excluded from snapshots.
- Snapshots are consistent archives of encrypted nodes and refs, suitable for
  off-host replication.
- Containers run as non-root with a read-only root filesystem and dropped Linux
  capabilities.

See [architecture](docs/architecture.md), [security](docs/security.md),
[API](docs/api.md), and [operations](docs/operations.md) for the full contract.
Agents integrating with Jaybase should use [llm.md](llm.md) as their operating
contract.

## Deploy in five steps

Prerequisites: a Linux host with Docker Compose, ports 80 and 443 reachable, and
an A/AAAA record pointing a domain at the host.

```sh
cp .env.example .env
# Edit .env and set JAYBASE_DOMAIN.

go run ./cmd/jaybase-server init ./secrets
# Save the three printed tokens in a password manager. They are shown once.

docker compose up -d --build
docker compose ps
curl https://jaybase.example.com/health/ready
```

The initializer refuses to replace existing secrets. The server also refuses to
start without an external data-key file and a valid hashed credential file.

## Append and read a fact

Fetch the current root first:

```sh
export JAYBASE_URL=https://jaybase.example.com
export JAYBASE_TOKEN='the-writer-token'

curl -fsS \
  -H "Authorization: Bearer $JAYBASE_TOKEN" \
  "$JAYBASE_URL/v1/root"
```

Use that root as `expected_root` and a new stable idempotency key for the logical
operation. An empty string is the expected root of a new database.

```sh
curl -fsS -X POST "$JAYBASE_URL/v1/events" \
  -H "Authorization: Bearer $JAYBASE_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: fact-primary-contact-v1-7f3d2a" \
  --data '{
    "type": "business.fact",
    "entity_id": "01JOPAQUE8F3K2M7Q9R4T6V1WX",
    "command": "fact assert",
    "payload": {"primary_contact": "Ada Lovelace"},
    "expected_root": ""
  }'
```

Readers get metadata by default. Payload decryption must be explicitly requested:

```sh
curl -fsS \
  -H "Authorization: Bearer $JAYBASE_TOKEN" \
  "$JAYBASE_URL/v1/events?include_payload=true&limit=100"
```

## Embedded library

```go
store, err := jaybase.OpenStore(".jaybase")
if err != nil { /* handle error */ }
defer store.Close()
root, err := store.Append(jaybase.Context{Actor: "agent"}, jaybase.AppendOptions{
    Type: "business.fact", Command: "fact assert", Payload: fact,
})
```

`OpenStore` retains the original local key fallback for compatibility and takes
an advisory single-writer lock at `.jaybase/.writer.lock` until `Close`.
It is a local-development convenience and co-locates the key with the data.
Production and all long-running hosted processes must use `OpenStoreWithDataKey`;
the bundled server enforces that choice.

Hosted mode also supports expiring credentials, add/revoke helpers, off-host root
pin checks, per-principal throttling, payload-read audit fields, streaming full
verification, and offline data-key migration. Follow the financial profile in
[security](docs/security.md) and the procedures in [operations](docs/operations.md)
before storing sensitive data.

## Verify

```sh
GOCACHE=/tmp/jaybase-gocache go test -race ./...
GOCACHE=/tmp/jaybase-gocache go vet ./...
docker compose config
docker build -t jaybase:test .
```

## License

AGPL-3.0-or-later. See `LICENSE`.

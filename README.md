<p align="center">
  <img src="docs/assets/jaybase-logo.png" alt="Jaybase logo" width="900">
</p>

# Jaybase

**A durable, verifiable fact store for AI agents that need to show their work.**

AI agents can do useful work, but they are not always careful record keepers.
They retry requests, act on stale information, hand work to other agents, and
occasionally change their minds. Once an agent is allowed to touch important
business data, “what does the database say now?” is no longer enough. You also
need to know what happened, who did it, and what the agent knew at the time.

Jaybase gives agents a shared history they cannot accidentally overwrite. Every
change is recorded as a new fact with an identity, a timestamp, and the command
that produced it. The history can be replayed, checked for unexpected changes,
and used to rebuild whatever view of the data you need today.

Jaybase preserves what was asserted. It does not decide whether an assertion is
true or apply your business rules for you.

## Who Jaybase is for

Jaybase is for developers and small teams building agents that take real action
on important data. It is a good fit when:

- an agent's work must survive a restart, a handoff, or a model change;
- you need a clear record of which agent or operator made each change;
- a timed-out request may be retried and must not create duplicate work;
- an agent acting on old information must not silently overwrite newer facts;
- corrections need to preserve the original claim and explain what changed; or
- sensitive business facts need to stay encrypted and under your control.

That makes Jaybase especially useful for accounting, operations, compliance,
approvals, and other workflows where the history matters as much as the latest
answer.

Jaybase is not trying to replace every database. If you mainly need joins,
dashboards, full-text search, low-latency current state, or many concurrent
writers across regions, use a conventional database or a mature distributed
event platform. Jaybase works best as the trusted fact history underneath those
systems.

## Why Jaybase exists

Traditional databases are very good at storing the current state of an
application. That is exactly what most applications need. But agent workflows
add a few awkward questions:

- Did the first write succeed before the agent timed out and tried again?
- Did another agent change the data after this decision was made?
- Was a fact corrected, or was the old value simply replaced?
- Can we reconstruct the inputs behind a decision months later?
- Can we tell if stored history changed after the fact?

You can answer those questions with SQL tables, audit triggers, application
logs, request IDs, and careful locking. The problem is that every application
has to design and enforce those rules correctly. Jaybase makes them the default
write path instead of optional conventions.

| When this happens | In a typical application database | In Jaybase |
| --- | --- | --- |
| An agent retries after a timeout | The application must detect and remove duplicates. | The same request returns the result of the first successful write. |
| Two agents act on the same old state | The last write may win unless the application adds locking. | The stale write is rejected so the agent can reconsider it. |
| A fact is corrected | An update can erase the value that came before. | The correction is appended and the original fact remains in history. |
| Someone asks for an audit trail | Logs and database rows must be pieced together. | The ordered history can be replayed and checked from a known root. |
| A product needs fast queries and reports | SQL is excellent at this. | Replay Jaybase into a SQL projection built for those queries. |

## How it works

Jaybase stores an ordered chain of events. Each event contains a type, an entity
ID, the command that produced it, the authenticated actor, a timestamp, and an
encrypted JSON payload. Each event also points to the event before it.

The normal write flow is:

1. The client reads the current `root`, which identifies the latest event.
2. It submits a fact with that `expected_root` and a stable `Idempotency-Key`.
3. Jaybase derives the actor from the credential, encrypts the payload with
   AES-256-GCM, and creates a SHA-256 address covering the metadata, ciphertext,
   and previous event.
4. Jaybase writes the event durably and then moves the root to the new address.
5. An identical retry returns the original event. A stale root or reused key
   with different content returns `409 conflict` instead of guessing.

Because every address depends on the event before it, editing old metadata,
ciphertext, or ancestry changes the hashes that follow. A saved root is a compact
commitment to the complete history behind it; pin roots off-host when you need
to detect a rewritten or replaced store.

Consumers read events in order and apply their own domain rules. A correction,
retraction, or approval is another event rather than an edit to old data. This
keeps the stored history simple while letting each application decide what the
facts mean.

Jaybase intentionally has one writer process per data volume. Many agents can
use the service, but writes are serialized through that process. This is a small,
understandable consistency model—not a distributed consensus system.

## Where SQL fits

Jaybase and SQL solve different parts of the problem, and they work well
together:

```text
agents and services
        |
        v
Jaybase: trusted fact history
        |
        | replay
        v
SQLite or PostgreSQL: current state, joins, search, reports, and APIs
```

Treat Jaybase as the source of truth for what happened. Build a SQLite or
PostgreSQL projection for the way your product needs to read the data today. If
the projection is lost or its schema changes, rebuild it by replaying Jaybase.

## Run Jaybase

Jaybase can run as a hosted HTTP service or as an embedded Go library. The
hosted service is the recommended boundary when several agents or applications
need the same fact history.

### Deploy the hosted service

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

### Append and read a fact

Fetch the current root first:

```sh
export JAYBASE_URL=https://jaybase.example.com
export JAYBASE_TOKEN='the-writer-token'

curl -fsS \
  -H "Authorization: Bearer $JAYBASE_TOKEN" \
  "$JAYBASE_URL/v1/root"
```

Use the returned root as `expected_root` and choose one stable idempotency key
for the logical operation. Use an empty string only for the first event in a new
database.

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
    "expected_root": "sha256:root-from-the-previous-response"
  }'
```

Readers get metadata by default. Payload decryption must be explicitly requested:

```sh
curl -fsS \
  -H "Authorization: Bearer $JAYBASE_TOKEN" \
  "$JAYBASE_URL/v1/events?include_payload=true&limit=100"
```

### Use the embedded Go library

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

## Production boundaries

- A single Jaybase process owns each writable data volume.
- Caddy terminates HTTPS and obtains certificates automatically.
- Bearer credentials map to `reader`, `writer`, or `admin`; plaintext tokens are
  never stored by Jaybase.
- Payloads are encrypted at rest. The data key is mounted separately from the
  volume and excluded from snapshots.
- Snapshots contain encrypted nodes and refs and should be copied off-host.
- Containers run as non-root with a read-only root filesystem and dropped Linux
  capabilities.

Hosted mode also supports expiring credentials, credential rotation and
revocation, off-host root checks, per-principal throttling, payload-read audit
fields, streaming verification, and offline data-key migration.

Read the [architecture](docs/architecture.md), [security](docs/security.md),
[API](docs/api.md), and [operations](docs/operations.md) guides before running
Jaybase with sensitive data. Agents integrating with Jaybase should use
[llm.md](llm.md) as their operating contract.

## Verify

```sh
GOCACHE=/tmp/jaybase-gocache go test -race ./...
GOCACHE=/tmp/jaybase-gocache go vet ./...
docker compose config
docker build -t jaybase:test .
```

## License

AGPL-3.0-or-later. See `LICENSE`.

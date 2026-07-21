<p align="center">
  <img src="docs/assets/jaybase-logo.png" alt="Jaybase logo" width="900">
</p>

# Jaybase

**A safer data layer for AI agents doing real business work.**

AI agents become genuinely useful when we can trust them with more than advice.
They need to read and write the same financial, operational, customer, and
compliance data that people use to run a business. If every change still needs a
human to copy, approve, and enter it, the agent is a helper—not an operator.

That level of trust is hard to grant. Traditional databases were designed as
backends for deterministic software: the code follows known paths, the schema is
controlled, and writes are expected to be intentional. Agents behave more like
people. They interpret context, make judgment calls, retry when outcomes are
unclear, and sometimes do surprising or incorrect things. Unlike people, they
can do all of that at machine speed.

Giving an agent direct access to a mutable database means one bad decision,
runaway loop, prompt injection, or compromised credential can overwrite or
delete critical data before anyone notices. Audit logs, request deduplication,
history, and rollback can be added to a traditional system, but they are not
usually inseparable from every write.

Jaybase exists to make high-trust delegation practical. Agents can read shared
business history and add new facts, but they cannot silently rewrite the past.
Every write is attributable, logged, retry-safe, checked against the state on
which the decision was based, and preserved for replay. When an agent is wrong,
the correction becomes part of the record instead of erasing the mistake.

The facts themselves stay flexible. An agent can introduce new JSON fields and
new fact types as its job evolves without migrating or rewriting old history.
The safety rules around those facts stay fixed.

Jaybase does not make an agent infallible or decide whether a fact is true. An
authorized agent can still assert a bad fact. Jaybase makes that action bounded,
visible, and correctable instead of silently destructive.

## Who Jaybase is for

Jaybase is for developers and small teams moving from read-only copilots to
agents that are allowed to operate. It is a good fit when:

- agents need to read and write critical business data without getting direct
  power to update or delete history;
- a mistake, retry loop, or malicious instruction must not be able to erase the
  source of truth;
- every action must be tied to an agent or operator and explainable later;
- bad decisions need to be reversible without pretending they never happened;
- the shape of the facts will evolve as the agent learns new jobs; or
- sensitive data needs to stay encrypted and under your control.

That makes Jaybase especially useful for accounting, operations, compliance,
approvals, and other workflows where the history matters as much as the latest
answer.

Jaybase is focused on protecting and preserving an agent-written fact history.
It is not designed for dashboards, full-text search, low-latency current-state
queries, or many concurrent writers across regions.

## Why Jaybase exists

Traditional databases are not bad databases. They are optimized for applications
whose deterministic code owns the rules around each read and write. Agents
change that assumption. The data layer now has to defend the business from a
caller that is useful precisely because it can make its own decisions.

| Agent systems need | A typical database requires you to add | Jaybase makes native |
| --- | --- | --- |
| A safe response to unexpected behavior or intentional misuse | Permissions and application code around every mutation and delete path | An append-only API, credential roles, server-owned identity, and request throttling |
| Reversible outcomes | Audit tables, backups, and custom rollback logic | Append-only facts and replay, so corrections and retractions do not delete history |
| Auditable decisions | A separate logging system kept in sync with database writes | The actor, time, command, and place in history on every event |
| Safe retries at machine speed | Application-specific request deduplication | A stable request key that returns the original successful result |
| Protection from stale decisions | Locking or version checks added by each application | A rejected write when the history changed after the agent read it |
| A model that evolves with the agent | Schema migrations or a custom document contract | Flexible JSON facts and new event types without rewriting old data |

All of these protections can be built around a general-purpose database.
Jaybase's point is that an agent should not depend on every application team
remembering to build them. They are part of the storage contract for every write.

## How it works

Jaybase separates flexible facts from a rigid safety boundary. The payload can
be any JSON your application understands, while the write protocol and history
rules do not change.

Under that boundary, Jaybase stores an ordered chain of events. Each event
contains a type, an entity ID, the command that produced it, the authenticated
actor, a timestamp, and an encrypted JSON payload. Each event also points to the
event before it.

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

That is what reversibility means in Jaybase: do not erase the bad action. Append
the correction, replay the history, and rebuild the current state. You can return
the business to the right outcome without losing the evidence of how it got
there.

The hosted API has no path for an agent to edit or delete earlier events. It also
does not let callers choose their own identity; the server derives the actor and
role from the credential. Least-privilege roles and per-principal throttling add
boundaries around unexpected behavior, runaway automation, and intentional
misuse.

Jaybase intentionally has one writer process per data volume. Many agents can
use the service, but writes are serialized through that process. This is a small,
understandable consistency model—not a distributed consensus system.

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

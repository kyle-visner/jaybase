# Operations runbook

## Initial deployment

1. Provision a patched Linux host with persistent storage and Docker Compose.
2. Point the chosen DNS name at it and allow inbound TCP 80/443 and UDP 443.
3. Clone the repository, copy `.env.example` to `.env`, and set the domain.
4. Run `go run ./cmd/jaybase-server init ./secrets` on a trusted machine. Save
   the printed tokens in a password manager.
5. Back up `secrets/data_key` to a separate secret store. Losing it makes every
   payload unrecoverable.
6. Run `docker compose up -d --build` and check `docker compose ps`.
7. Call `/health/ready`, append a test fact, read it back, trigger a snapshot, and
   copy that snapshot off-host.

Compose publishes only Caddy. Jaybase port 8080 stays on the private Compose
network.

## Routine backup

Call the snapshot endpoint with an admin token:

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $JAYBASE_ADMIN_TOKEN" \
  "$JAYBASE_URL/v1/admin/snapshots"
```

The response names an archive in `/var/backups/jaybase` inside the Jaybase
container. Copy it to a different machine, account, or object-storage service.
A snapshot left only in the local Docker volume is not a backup.

Keep these items in separate failure domains:

- snapshot archive;
- `secrets/data_key`;
- an operator record containing the snapshot root and timestamp.

Use a scheduler on the host or in an external automation system to trigger and
export snapshots. Do not place the admin token directly in a crontab; read it
from a root-owned credential file or secret manager.

## Integrity check

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $JAYBASE_ADMIN_TOKEN" \
  "$JAYBASE_URL/v1/admin/verify"
```

Run this periodically and before declaring a backup good. It checks the hash
chain and authenticates every encrypted payload.

## Restore drill

Always restore into a new empty volume first:

1. Stop the candidate Jaybase instance.
2. Extract the archive into a new empty data volume. The archive contains
   `objects/` and `refs/`; it intentionally contains no `keys/` directory.
3. Mount the original data-key secret and the desired auth file.
4. Start Jaybase without exposing it publicly and wait for readiness.
5. Call `/v1/admin/verify`, compare the returned root with the off-host backup
   record, and read representative facts.
6. Only then switch traffic or DNS to the restored instance.

Never test restoration by overwriting the only production volume.

## Migrating an existing local store

An existing `.jaybase` directory can move without rewriting its history:

1. Stop every process that can append to the local store.
2. Save `.jaybase/keys/data.key` as the hosted `secrets/data_key`.
3. Copy `.jaybase/objects` and `.jaybase/refs` into a new hosted data volume.
4. Do not copy `.jaybase/keys` into that volume.
5. Start hosted Jaybase with the saved external key and run the admin verify call.
6. Compare the hosted root with the last local root before allowing writes.

Keep the original local directory read-only until the hosted restore and backup
drill succeeds.

## Updating

Before an update, create and export a snapshot. Then rebuild and recreate:

```sh
git pull --ff-only
docker compose build --pull jaybase
docker compose pull caddy
docker compose up -d
docker compose ps
```

Finish with readiness, integrity, append, and replay checks. Review release
changes before updating across schema versions.

## Incident priorities

If a token is exposed, revoke its digest and recreate the service immediately.
If the data key may be exposed, isolate the host, preserve logs and volumes, and
treat every payload as compromised. This version cannot rotate the data key in
place; migrate validated facts to a freshly keyed store after the incident.

If integrity verification fails, stop writes, preserve the current volume, and
compare its root and node set with off-host snapshots. Do not repair files in
place before capturing forensic copies.

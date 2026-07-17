# Security model

## What the reference deployment protects

- HTTPS protects credentials and payloads in transit.
- Role-scoped bearer credentials separate read, write, and administrative work.
- Only SHA-256 token digests are stored in `auth.json`.
- AES-256-GCM protects payload confidentiality and authenticity on the data and
  backup volumes.
- The data key is mounted from a separate file and is never written into hosted
  storage or snapshot archives.
- Content hashes and parent links expose modification of any node reachable from
  the current root.
- Payloads are omitted from normal event-list responses unless the caller opts in.
- Request bodies are capped, unknown JSON fields are rejected, and server timeouts
  bound slow clients.
- The application container is non-root, read-only except for data/backup
  volumes and a small tmpfs, and has all Linux capabilities removed.

## What it does not protect

- A host-root compromise can read the mounted data key and live process memory.
- An authorized reader can exfiltrate decrypted facts.
- An authorized writer can append false facts; append-only history provides
  attribution, not truth validation.
- SHA-256 links alone do not prevent an attacker with full storage control from
  rolling the database back to an older valid root. Retain root values and
  snapshots in a separate trust domain to detect rollback.
- Metadata such as event type, entity ID, actor, command, timestamp, and graph
  shape is not encrypted.
- This release does not re-encrypt an existing chain under a new data key.

## Secret handling

Run `jaybase-server init` on a trusted machine. Put the printed plaintext tokens
in a password manager and deliver only the minimum-role token to each agent.
Keep `secrets/data_key` in a separate backup system from Jaybase snapshots.

To rotate an API token:

1. Generate a random token with at least 32 bytes of entropy.
2. Hash it with `jaybase-server hash-token` (the token is read from standard input).
3. Add a new ID/role/digest record to `secrets/auth.json`.
4. Recreate the Jaybase container and move clients to the new token.
5. Remove the old record and recreate the container again.

Never put plaintext tokens in `auth.json`, Compose environment variables, command
arguments, source control, or request URLs.

## Host hardening checklist

- Patch the host and container images regularly; Dependabot tracks image and
  GitHub Actions updates in this repository.
- Permit inbound 80/443 and restricted administrative SSH only. Do not publish
  Jaybase port 8080.
- Use full-disk encryption where the hosting provider supports it.
- Send container logs to a restricted destination; Jaybase never logs bodies or
  authorization headers.
- Copy snapshots off-host after every backup and retain multiple generations.
- Record the returned root in the off-host backup log. Alert if a previously
  observed root is no longer in the current history.
- Periodically call the authenticated verify endpoint and perform a restore drill.

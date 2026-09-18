# Jay Berth — Security & trust product-truth brief

For Brand. CoS handoff. Grounded in code and current production only. Do not publish this file. Use it to write `/security`. Prefer understatement.

**Scope of evidence (2026-09-18):** `kyle-visner/jaybase` (this repo), `magpie`, `martin`, `jaybase-host`, `command`. Folio GitHub repo exists and is empty. Parked Brand page: [Jay Berth — Security & trust page ON HOLD](https://docs.google.com/document/d/1gpHSBVTtDnKF92cBiOThUqrNcmjleJgyw1JGv667SSk). Older Avian Suite `/trust` page lives in `jaybase-host` (`web/public/trust.html`) and overclaims in places. That is a different product surface than Jay Berth.

Label key: **ships today** / **partial** / **not yet**.

---

## 1) Auditability

What actually exists is an append-only store and CLI/MCP history reads. There is no Jay Berth buyer UI that shows “which record, which field, when.”

**Ships today**

- JayBase stores a linear hash-linked event chain. Each event has type, entity id, command, actor, role, timestamp, parent hashes, request id, and an AES-256-GCM payload. Hash covers metadata plus ciphertext. (`storage.go` `Node`; `GET /v1/events` in `server/server.go`; `docs/api.md`)
- Actor and role on a hosted write come from the bearer credential, not the request body. Callers cannot pick their identity. (`server/server.go` `appendEvent`; `server/auth.go`)
- Named refs exist (`GET/PUT /v1/refs/{name}`). They are checkpoints, not a UI timeline.
- Structured HTTP access logs record principal, path, status, and (for payload reads / admin ops) outcome and event ids. Logs omit bodies and `Authorization`. They are process stdout, not a customer audit product. (`server/server.go` `accessLog`)
- Magpie `audit` / MCP `audit` returns metadata-only events (no payloads). Requires `audit:read`. Magpie also persists `rbac.role` / `rbac.user` events. (`magpie` `book.go`, `rbac.go`, `docs/SECURITY.md`)
- Magpie payload wrapper is `{kind, data}` (`eventEnvelope` in `magpie/internal/magpie/storage.go`). That is the “envelope” in code. Signed command envelopes are **not yet**.
- Martin records are `martin.*` events on the same store. Archive / cancel / merge / supersede. No delete of CRM history. Audit output is metadata-only. (`martin/docs/SECURITY.md`, `docs/FACTS.md`)
- Magpie treats `folio.*` (and other foreign `app.*`) as someone else’s events: skip payload fetch, keep the shared root. (`magpie/README.md`)

**Partial**

- “You can see who wrote what” is true at the **event** layer (credential id + role + hash). It is not a field-level change log and not a shareable human history screen.
- Agent tokens: JayBase `reader` / `writer` / `admin` bearers; hosted JayBase MCP `jb_live_…` tokens (hashed, grant/revoke). Magpie `--actor` and Martin `--actor` are **not** proven by the JayBase token. Command Finance hard-codes Magpie actor `owner`. (`jaybase-host/internal/control/store.go`; `command/internal/hypercanvas/tenant/tenant.go`)
- Session cookies exist on **Command** (hashed session token, 30 days) and **jaybase-host** operator/account cookies (`avian_op`, `avian_acct`). They are not bound onto JayBase event actor fields.

**Not yet**

- Folio / Jay Berth event-log UI, store browser, or “inspect in the same UI you explore data.” `kyle-visner/folio` is empty. Command UI is books + chat (`command/DESIGN.md`), not a store inspector.
- Folio Tables, if it appears later, is a current-state grid. It is not the store. Intended inspection surface is a store browser (path B). That browser is **not in any repo we could read**. Do not say it ships until Kyle points at a build.
- Centralized immutable audit export, WORM log, or customer-facing “what did the agent do?” report.

---

## 2) Recovery

Distinguish **append a correction** (product) from **undo / restore / export** (mostly ops or missing).

**Ships today**

- Hosted JayBase API has no update or delete of history. A fix is a new event. Stale `expected_root` or reused idempotency key with different content returns `409`. (`README.md`, `llm.md`, `POST /v1/events`)
- Magpie will not persist an unbalanced journal. Bank/ledger mistakes are reversed or reclassified with an audit reason, not edited in place. (`magpie/docs/SECURITY.md`, README capabilities)
- Martin archives / cancels / merges / supersedes. No CRM history delete.
- JayBase admin snapshots (`POST /v1/admin/snapshots`) write a keyless encrypted archive. Restore is a **manual** extract into a new volume. No restore API. (`snapshot.go`, `docs/operations.md`)
- Magpie / Martin `snapshot create` writes a **named root checkpoint**, not an off-host backup and not a point-in-time restore command. Magpie README lists “point-in-time restore” as out of scope.
- Replay from events is how current state is rebuilt. The client (Magpie, Martin, or an agent) replays. JayBase does not materialize entities.
- Bounded replay (`after`, `root` on `GET /v1/events`) is how you read history up to a known tip. That is not a user “time-travel” product.

**Partial**

- Command tenants each get their own Magpie book under `tenants/<id>/book` (own keys, objects, root). Two businesses do not share a book. (`command/internal/hypercanvas/tenant/tenant.go` `Init`)
- Whether live Command vs Zorza books on `command-hostinger` are two such tenants: **Kyle confirm**. Code supports separate books. We did not inspect the live volume.

**Not yet (do not say these)**

- Revert / undo any agent write
- Soft-delete of the store or of events
- Customer export product (“ask your AI to export at any time,” trial wind-down export, 7-day read-only grace)
- Magpie/Martin one-click restore
- Rebuild-from-events as a button in a Jay Berth UI

Parked Brand recoverability copy (“fix the record that went wrong,” “not permanent destroy”) is **intent**, not a shipped control. Honest today: a bad write stays in history; you append a correction if the app supports that write.

---

## 3) Hosting / trust surface (production today only)

Two live hosts. Do not mix them in public copy.

### A. `command-hostinger` (Command private preview)

Source: `command/DEPLOYMENT.md`, `compose.yaml`, `HOSTING.md`.

**Ships today**

- Tailnet-only. App binds `127.0.0.1:17474`. Tailscale Serve at `https://command-hostinger.tail3e5e03.ts.net`. Funnel off. Public IP does not serve the app.
- TLS is Tailscale Serve (tailnet HTTPS / Tailscale CA), not a public Let’s Encrypt site. Not a public Jay Berth launch.
- One Docker service, UID 10001, read-only root, caps dropped, `command_data` volume. Isolation between books is **directories + session/tenant checks**, not per-tenant processes or a multi-tenant kernel. (`HOSTING.md` threat model)
- Access: magic-link sign-in (email unset; preview returns the link on the page). Session token hashed in `platform/auth.json`. Passkeys on this host still only accept localhost:7474. Production public-origin cookies / emailed magic links are **not** this deployment.
- Magpie is the only book writer. Command actor is `owner`.

**Not yet / do not claim for this host**

- Automated off-host backups. Deploy notes say none were configured. The volume is persistence, not a backup. Host root and Docker admin can read volume and env.
- Application encryption for Command auth, chat, memory, evidence, or connector tokens. Only the Magpie/JayBase book payloads use store encryption. (`HOSTING.md` data-class table)
- Public HTTPS, abuse controls, SMTP, live bank connections, or live billing on this instance.

### B. Hosted JayBase / Avian Suite (Vultr + Tailscale)

Source: `jaybase-host/status.md`, `deploy/docker-compose.yml`. Different product (`jaybase.tail3e5e03.ts.net`). Gateway is multi-tenant; **each customer gets a separate JayBase data directory and process**. Engine is still single-tenant per store. MCP bearer `jb_live_…`. Operator `/app` is founder dogfood. SMTP unset. Not Jay Berth / jayberth.com.

### C. JayBase reference Compose (this repo)

Caddy terminates public TLS + HSTS (`deploy/Caddyfile`). Data key is a separate file, excluded from snapshots. **This is the engine recipe, not proof of how Jay Berth is hosted today.**

---

## 4) Explicit NO-claims list

Brand must not say:

- SOC 2, ISO, HIPAA, PCI, FedRAMP, DPA, subprocessors list, pen-test badge, uptime SLA, status page
- “Encrypted at rest” for the whole product. True for **JayBase event payloads** only. Metadata (type, entity id, actor, role, command, time, parents) is plaintext. Command/platform files are not application-encrypted. Host disk encryption: unknown
- “Encrypted on the way in” as a Jay Berth public-site claim. True on Tailscale for the private Command host; not a public CA site
- “Undo any agent write,” “not permanent damage,” “time-travel,” “soft-delete,” “export anytime,” “7-day read-only then soft-delete”
- Field-level audit in the UI, or inspect-in-the-same-grid
- Multi-agent catch / other agents fix mistakes before you notice
- Signed command envelopes (listed as future in Magpie/Martin SECURITY.md)
- Magpie `--actor` is authenticated identity
- Multi-tenant kernel / per-customer process isolation on Command
- Off-host backups, tested restore, or residency (“in the U.S.”) for Jay Berth (Vultr ewr is Avian Suite host; Command Hostinger region not locked for public copy)
- Jay Berth / jayberth.com is live as a public hosted product
- Avian Suite `/trust` lines as Jay Berth copy (“closed source,” “export anytime,” “agent cannot run the box”)
- Truth validation: an authorized writer can append a false fact. Hash chain proves history shape, not that the fact is true. (`llm.md`, `docs/security.md`)

---

## 5) Magpie / Martin / store-browser

- Magpie and Martin are **apps on JayBase**, not Jay Berth. They matter for trust as the place `ledger.*`, invoices, CRM events actually live and can be listed.
- Trust-relevant Magpie reads: `audit` (metadata), reports (JSON/CSV), named snapshots. Trust-relevant Martin reads: metadata audit, archive (not delete).
- Folio Tables-only (current-state grid) ≠ the store. Do not imply a table view is the audit log.
- Store browser (path B) is the intended inspection surface. **Product intent. Not in visible source.** Until it is in a repo or a Kyle-confirmed live build, Brand may say agents write into JayBase history you can replay. Do not say customers have a store browser today.

---

## Open questions / need Kyle confirm

1. Is any Folio / store-browser / Tables UI live on a private host, or only intended? Folio repo is empty.
2. Are Command and Zorza two separate live books on `command-hostinger`?
3. Should Jay Berth `/security` mention Command tailnet preview at all, or only speak to JayBase mechanics until a public host exists?
4. Public wording for payload encryption vs “the host can still read keys/memory”?
5. Any off-host backup or restore drill since `command/DEPLOYMENT.md` said none?
6. Is Avian Suite `/trust` being retired so it cannot contradict Jay Berth?

**Safe one-liner Brand can use (Track B, still understated):**  
JayBase keeps an attributed, hash-linked history of writes. The API cannot rewrite or delete that history. A correction is a new event. Inspection today is the event API and Magpie/Martin audit tools, not a Jay Berth security console.

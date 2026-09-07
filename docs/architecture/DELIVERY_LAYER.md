# Delivery Layer v1

Status: implemented and tested
Scope: `nth_dao/delivery/` - transport-agnostic signed envelope delivery

## What This Is

The common protocol spine described in the integration design doc §5 and §9:
every domain event travels as a signed `TransportEnvelope` through pluggable
transports, is queued in a durable outbox, is validated by a fail-closed
inbox, and is routed by policy rather than a fixed fallback order.

```
Domain (channel / task / mission / market / mandate)
        │  business event → payload
        ▼
TransportEnvelope v1  (canonical JSON, Ed25519, content-addressed)
        │
   ┌────┴────────────────────────────────────────────┐
   │ DurableOutbox          DeliveryInbox            │
   │ JSONL journal,         size→sig→TTL→nonce→      │
   │ crash-safe, ACK-       dedup→authorize,         │
   │ terminal               persistent replay cache  │
   └────┬────────────────────────────────────────────┘
        ▼
DeliveryRouter  (policy-scored; no fixed fallback order)
        │
   ┌────┼──────────────────┬───────────────────────┐
   │ loopback-hub       │ loopback-mesh          │ file-bundle      │
   │ (central relay)    │ (federated broadcast)  │ (offline carry)  │
   └────────────────────┴────────────────────────┴──────────────────┘
```

## Module Map

| Module | Responsibility |
|---|---|
| `delivery/envelope.py` | `TransportEnvelope v1` — canonical JSON, content-addressed `message_id`, author signature, TTL, nonce, hop routing |
| `delivery/acknowledgement.py` | signed `DeliveryAck` bound to `message_id` + received wire digest |
| `delivery/outbox.py` | `DurableOutbox` — JSONL journal, fsync-per-event, crash recovery, ACK-terminal, bounded |
| `delivery/inbox.py` | `DeliveryInbox` — ordered fail-closed pipeline + persistent replay cache |
| `delivery/policy.py` | `RoutePolicy` — pure validated routing policy (centralized / decentralized / offline presets) |
| `delivery/router.py` | `DeliveryRouter` — deterministic scoring, fallback, health cooldowns |
| `delivery/transports/base.py` | `Transport` ABC + capabilities + health |
| `delivery/transports/loopback.py` | hub (central relay) / mesh (federated broadcast) in-process endpoints |
| `delivery/transports/file_bundle.py` | signed file-bundle exchange (USB / shared dir / manual carry) |
| `delivery/plugin_runtime.py` | durable bridge to the Host-governed `org.nth-dao.transport.delivery` capability |

## Control Plane

`PluginHost` is the normative lifecycle and authorization boundary for
production transport providers. Providers are reached only through a revocable
`ProviderBinding` and an `InvocationAuthority` whose destination resource scope
is checked by the Host. `PluginDeliveryRuntime` composes that governed provider
with `DurableOutbox` and `DeliveryInbox`:

1. A sender durably enqueues the signed envelope before invoking `send`.
2. A receiver obtains an exclusive leased batch through the Host.
3. Every item is independently revalidated and persisted by `DeliveryInbox`.
4. The runtime acknowledges the provider lease only after the complete batch is
   durable. A crash before acknowledgement causes safe redelivery and inbox
   deduplication.

The classes implementing the lower-level `Transport` ABC remain useful for
adapters, isolated tests, and migration. They do not grant plugin authority and
must not be treated as a second governance plane. A network transport becomes a
production provider only after it implements the plugin capability and is
explicitly installed, authorized, and enabled by the Host. The built-in
loopback provider is installed disabled by default.

## Wire Contract (v1)

* Envelope serializes to `nth_dao.canonical_json` bytes; transports carry it
  opaquely and must not re-encode it.
* `message_id = sha256(canonical(content_body))` where `content_body` is the
  author-signed projection minus `signature`, minus `message_id` itself, and
  minus the mutable `routing.hop_count`. Identical content always yields the
  identical id; relays forwarding with `hop_count + 1` preserve it.
* The signature covers `signing_body` = everything author-owned **including**
  the `message_id` (the content address is signed) and excluding
  `routing.hop_count`.
* Relays may only change `routing.hop_count`, bounded by the signed
  `routing.hop_limit`; `forward_envelope` fails closed at the budget.
* ACKs are signed by the receiver and bind `message_id` plus the exact wire
  digest received. Senders accept only the origin digest or a digest obtained
  by changing `hop_count` within the author-signed hop limit. A relay cannot
  use the mutable hop field to authorize any other envelope change.

### Limits (fail closed, all pinned by vectors/tests)

`MAX_PAYLOAD_BYTES=256 KiB`, `MAX_ENVELOPE_BYTES=512 KiB` (matches the
plugin transport wire limit), `MAX_PAYLOAD_DEPTH=16`, `MAX_TTL_MS=7 days`,
`MAX_CLOCK_SKEW_MS=5 min`, `MAX_HOP_LIMIT=16`, nonce 16–128 alnum,
`MAX_SAFE_INTEGER=2^53−1`.

## Design Decisions and Deviations

1. **Synchronous Transport interface.** The design doc §5.2 sketches an
   `async def` interface. The existing core (gossip, mission CAS, commerce
   outbox, plugin transport contract) is synchronous; introducing a second
   async boundary would create the exact "parallel system" §3 forbids.
   Async adapters can wrap the sync contract without protocol changes.
2. **Content address excludes `message_id` itself.** First draft derived
   `message_id` from a body that contained it — a non-converging self
   reference caught by tests. The address is derived from
   `content_body()`; the author then signs the address.
3. **One ACK rule, two binding fields.** The ACK binds what the receiver
   verified (wire digest) and what the sender matches (message_id). Digest
   equality against the sender's origin copy is deliberately NOT required:
   forwarded mesh copies differ in `hop_count` bytes.
4. **Router scores; policy decides.** No hardcoded "BLE → WS → Nostr"
   ladder (§8.2). Scoring: realtime preference (+4), privacy level (+1 per
   level), no external infrastructure (+2), healthy streak (+1); ties keep
   registration order. Failing transports cool down after 3 consecutive
   failures for 30 s (constants on `DeliveryRouter`).
5. **Journal-first persistence.** Outbox and inbox mutate memory only
   after the journal line is fsynced. A torn final line (crash mid-append)
   is ignored on reload; corruption anywhere else raises. Both journals are
   bounded with explicit compaction (`compact` / `compact_rejections`).
6. **Live cross-process dedup.** Inbox/outbox re-fold their journal when an
   mtime/size change from another process is observed, so dedup works
   across processes without a broker.
7. **bitchat borrowings.** Controlled-flood prerequisites
   (hop TTL, content-addressed dedup, jitter budget left to transports),
   courier-style store-and-carry (file bundle is the v1 courier), and
   router-tiering are absorbed into the envelope + router contracts; no
   bitchat code is copied (Swift, public domain — patterns only).

## Threat Coverage Mapping (design doc §10 → mechanism)

| Threat | Mechanism |
|---|---|
| forged author / pubkey swap | Ed25519 verify against `sender_did` did:key |
| nonce replay, expiry | inbox pipeline steps 3–4, persistent cache |
| relay mutation of signed fields | signature covers author fields; only `hop_count` mutable |
| duplicate delivery across transports | `message_id` dedup in inbox; first signed ACK cancels outbox copies |
| ACK forgery | ACK signed by `receiver_did`; outbox verifies before terminal transition |
| oversized / deep flooding | byte + depth caps in envelope and inbox |
| crash between write and ack | journal-first + fsync; torn-tail recovery |
| clock skew attack | future-dated creation beyond 5 min rejected |
| accidental journal corruption | strict event shapes, canonical bytes, signature revalidation, and content binding fail closed |

The JSONL journals are crash-safe durability records, not tamper-evident
ledgers. A principal that can rewrite local files can delete or reorder journal
events. Deployments that include a hostile local-user threat must place the
workspace behind OS access controls and replicate audit evidence to an
independent signed or immutable store.

## Conformance

`delivery_envelope_v1` and `delivery_ack_v1` categories in
`nth_dao/conformance/vectors.json` contain ten fixed vectors covering canonical
bytes, content addresses, wire digests, signatures, time bounds, version
gates, and tamper failures. A non-Python port is wire-compatible when its
equivalent runner reports zero failures.

## Phase 1 — Real Transports (implemented)

The design doc §8.1 first priority is done: both existing network stacks are
now delivery Transports, borrowed as-is (no new wire protocol).

| Module | Role |
|---|---|
| `transports/websocket_gossip.py` | sync adapter over the borrowed async `GossipNode` (background loop thread, `run_coroutine_threadsafe` bridging). Outbound: the canonical envelope JSON is the content of one node-signed `ChannelMessage`; inbound: node-signed gossip is queued as envelopes for `poll()`. Trust stays in the borrowed layer (`require_signature=True`, pinned pubkeys / web-of-trust). `TeamChannel` is deliberately bypassed — it truncates content at 10 000 chars, which would destroy 512 KiB envelopes; the shim channel signs the identical payload shape without truncation or ledger. |
| `transports/federation.py` | client `FederationTransport` (POST canonical envelope bytes to every configured peer `/delivery/ingest`, strict per-peer timeout, bounded overall fan-out deadline, no redirects followed, response reads capped) and a stdlib `FederationIngestServer` (exact path, Content-Length capped with bounded 413 drain, canonical-bytes discipline, per-connection timeout, concurrency gate with 503, `DeliveryInbox` performs all validation). Core stays zero-dependency. |

ACK return path: the receiver wraps its signed `DeliveryAck` as an ordinary
envelope (`kind="delivery.ack"`, payload exactly `{"ack": ...}`); the host
unwraps via `ack_from_envelope` after inbox validation, which also enforces
that the envelope author IS the ACK receiver.

Borrowed-layer fix found during integration: `GossipNode.start()` built its
URL from the constructor port, so `port=0` (OS-assigned) produced a
`ws://host:0` URL — `start()` now reads the bound socket and the `url`
property reflects it.

Integration tests: `tests/test_delivery_integration_phase1.py` — full
outbox → router → real-wire → inbox → signed-ACK-return → delivered flows
for both HTTP federation and the gossip mesh, router policy selection
between the two real transports, gossip→federation fallback inside one
`send()`, and authorize-hook rejection at the ingest door (valid signature,
no allowlist entry → 422 → `peers-unreachable`).

## Phase 2 - Nostr Relay Tier

`nth_dao/nostr/` wraps the maintained `nostr-sdk` binding (optional extra
`nth-dao[nostr]`): secp256k1 BIP340 keys, NIP-01 events, and relay wire
protocol are all borrowed. NTH-specific mapping: `NostrKeyBinding` (an NTH
Ed25519 identity signs ownership of one Nostr key, one-year validity) and
kind-30078 envelope events whose `d` tag pins the envelope message_id —
receiver-side verification is two-tier (event signature via nostr-sdk,
envelope author signature via the delivery layer) and the d tag must
address the carried envelope (round-12: slot-collision and non-integer
timestamps fixed). Relay client (N2) and transport adapter (N3)
implemented: `NostrRelayClient` bridges the borrowed async relay pool on a
background thread (same pattern as the gossip adapter); `NostrTransport`
plugs into the delivery router with `PRIVACY_PUBLIC_RELAY` + broadcast
capabilities. Tested against an in-process fake NIP-01 relay: long-lived
subscription delivery, publish round-trip, hostile-relay rejection, key-binding
rotation/conflict handling, and private-tier refusal.

## Adversarial Review Record

Round 20 (adversarial review of every remaining commit: Phase 1 6182f4c,
Slice B bf28c9a, Phase 2 N1 ac92d5a, N2/N3 d104bf9, fix commits
0bb3209/bd71e5a/f1e4cae) found and fixed 1 resource leak; 19 hypotheses
probed and cleared:

| # | Defect | Fix |
|---|---|---|
| GG-16 | `NostrRelayClient._subscribe_async` overwrote `_stream_task` without cancelling the previous pump — a second `subscribe_events` call leaked the first coroutine forever | previous task cancelled before replacement |

Cleared by probe: BOM-prefixed JSON bodies (canonical-bytes discipline
rejects), deque flood performance (0.4ms/10k ops), file-bundle naming
idempotency, adapter-runtime fd lifecycle (GC + OS reclaim), glob on
10k-file directories (33.6ms), event-loop json.loads cost (0.13ms/200KB),
identity-probe side effects (constructor is pure), repeated-import cost
(cached), fake-relay set iteration (single-loop async), stderr cap
asymmetry (65KB diagnostic headroom by design), poll chaining (bounded per
call, remainder queued), HTTPError fp-None handling, binding-less sends
(already logged), NIP-40 expiration arithmetic (int-typed by validation).

Round 19 (adversarial review of the Phase-0 core as shipped in 64d92a1)
found and fixed 1 contract hole; 10 further hypotheses probed and cleared:

| # | Defect | Fix |
|---|---|---|
| FF-5 | `envelope_digest()` silently digested ANY dict — callers could compute digests over malformed shapes and bind them into ACKs and outbox records | plain dicts now require the exact envelope field set before digesting |

Cleared by probe (no fix needed): forward without TTL check (defense in
depth — inbox owns the clock), copy_count vs transport count (min-clamped),
hub first-poller-wins (by-design at-most-once for a shared recipient),
compact lock ordering (refold inside the cross-process lock), ACK
future-time skew, payload mutability through content_body, accept-path
refold, to_dict deepcopy cost at 100KB payloads (3.4ms).

Round 17 (design/security/operability review of the Nostr core) found and
fixed 2 findings; each has a pinned test or a documented boundary:

| # | Item | Fix |
|---|---|---|
| BB-w2 | No NIP-40 expiration tag on envelope events — expired envelopes remain world-readable on relays indefinitely | `["expiration", str(expires_at_secs)]` tag added, derived from the envelope's TTL |
| BB-x2 | `health()` only checks the transport's own running flag, not relay connection state | documented limitation: nostr-sdk handles reconnection internally; relay-level health requires the N3 continuation |
| BB-y2 | module docstring lacked an immutability warning | "WORLD-READABLE and IMMUTABLE" — not all relays honor NIP-40 deletion |

Round 16 (adversarial review of the Nostr transport) found and fixed 2
operability findings:

| # | Item | Fix |
|---|---|---|
| DD-a | `NostrTransport.send()` did not pass the binding through to `envelope_event` — the N1 publish-side enforcement (CC-c) was bypassed at the transport tier | `binding` parameter added to the transport constructor and wired into `send()` |
| DD-d | subscription setup failure in `start()` left the transport broken (publish + poll both dead) | subscription failure caught and logged; transport degrades to publish-only mode |

Round 15 (whole-stage review of the cumulative fixes) found and fixed 3
findings across the three deliverables:

| # | Item | Fix |
|---|---|---|
| CC-b | `envelope_event` accepted single-recipient (did:key) envelopes onto the world-readable relay tier — the round-14 warning had no technical enforcement | public-tier policy enforced: broadcast recipients (dao:/channel:) only |
| CC-c | an envelope could be published under a relay key that no verified binding delivers (publish-side binding enforcement missing) | optional `binding` param verified at publish: standalone signature check against the DID-decoded pubkey, key match, sender match |
| CC-a | the file-bundle import journal was unbounded (memory + startup DoS via valid-member flooding) | byte cap with newest-half rotation — safe because the inbox dedups redeliveries by message_id (pinned by the design-contract test) |

Round 14 (design/security/operability review of the Nostr core) hardened
the tier; each item has a pinned test or a documented boundary:

| # | Item | Fix |
|---|---|---|
| BB-u | extreme-depth hostile content (100k nesting) — RecursionError added to the catch list as defense-in-depth (probe showed the stack holds via the Rust serde boundary + field-set check) | hardening |
| BB-v | no explicit warning that relay content is world-readable | operability/security warning in the module docstring; N3 must enforce public-tier-only |
| BB-w | binding discovery/disambiguation unspecified for N3 | documented: transport allowlists are fed exclusively by VERIFIED bindings, latest-wins per NTH did |
| BB-x | `nostr-sdk` is pre-1.0 — API churn risk | pinned `>=0.45,<0.46` |
| BB-y | envelope rejections were silent | module logger warns with the reason |

Round 13 (full-test hunt on the Nostr core) found 1 validation-theater bug;
pinned by tests:

| # | Defect | Fix |
|---|---|---|
| BB-t | `envelope_event` validated `created_at_seconds` then silently DROPPED it (wall clock applied instead) — validation theater; deterministic replay was impossible | the timestamp is now applied via `custom_created_at`; same envelope+keys+timestamp reproduces the same event id (pinned), different timestamps produce different ids (pinned); BIP340 aux-random signatures documented as spec-allowed |

Also swept with no findings: unicode Content-Length probes, d-tag
extraction edge cases (empty value, multiple tags — first-tag semantics
matches NIP-01 replaceable rules).

Round 1 (pre-review) fixed: journal-first ordering for the replay cache,
journal size caps, expired-envelope enqueue rejection, and an in-function
import.

Round 2 (full-dimension hostile review) found and fixed 8 defects before
merge; each has a pinned regression test:

| # | Defect | Fix |
|---|---|---|
| A | `validate_envelope` raised (contract violation) on out-of-range integer timestamps instead of returning `(False, reason)` | gates converted to tuple returns; `now_ms` hardened against bool/oversize |
| B | `record_attempt` accepted attempts on already-DELIVERED records | `_require_live` rejects delivered records |
| C | `compact()` did not re-fold first — records another process enqueued were silently DROPPED | stat-based `_refold_if_changed` on outbox; compact/enqueue/get/pending re-fold before acting |
| D | inbox rejection journal grew without bound under a malformed-input flood | byte-budget auto-trim (75% of 4 MiB cap, newest kept) |
| E | file-bundle `poll` read a bundle into memory before its size check | stat-before-read |
| F | deterministic bundle temp filename — two same-content senders could collide mid-write | unique tmp name (pid + random), cleanup on failure |
| G | `version: true` (JSON bool == 1) passed the bundle version check | strict non-bool int check |
| H | inbox `_remember` mutated memory (eviction pop) BEFORE the durable write — a disk failure left memory diverged from the journal fold | peek-then-mutate: memory changes only after fsync |

Round 4 (reviewing the review fixes themselves) found and fixed 4 defects
in the round-2/3 fixes; each has a pinned regression test:

| # | Defect | Fix |
|---|---|---|
| Q | outbox `_append`, inbox `_remember`, and file-bundle `_append_imported` sampled their journal fingerprint AFTER releasing the cross-process lock — an append by another process inside that window was absorbed into "our" fingerprint and hidden from the re-fold check forever | fingerprint captured via `os.fstat` while STILL holding the lock (all three sites, plus `compact`) |
| R | inbox rejection-journal trim and `compact_rejections` used a deterministic temp name, and the flood-trim ran without the cross-process lock — concurrent trims could corrupt the temp file or drop lines | both paths locked, unique tmp names, failure cleanup |
| S | file-bundle `poll` had a stat-then-read gap: a courier swapping in a larger file between the two calls still got the big file read | post-read size re-check restored alongside the pre-read stat |
| T | `validate_ack` computed `canonical_json(ack.to_dict())` twice | computed once |

Round 3 (second full-dimension hostile review) found and fixed 5 further
defects plus one test-coverage gap; each has a pinned regression test:

| # | Defect | Fix |
|---|---|---|
| I | `compact()` re-folded OUTSIDE the cross-process lock — a TOCTOU window let another process's just-appended record be silently dropped by the `os.replace` | refold moved inside the lock; append-after-refold is now impossible |
| P | inbox `_remember` never updated `_journal_stat` after its own write, so every accept() re-folded the whole journal — O(n) per accept, O(n²) cumulative at cache scale | own-write stat refresh; re-folds now only happen for OTHER processes' appends |
| J | `routing.reply_to: null` (explicit JSON null) validated OK for foreign senders — two encodings of one semantic value | explicit null refused; absent-or-non-empty-string only |
| K | file-bundle import journal appended without the cross-process lock, and the imported set never re-folded — shared state dirs double-delivered | InterProcessLock + stat-based re-fold, mirroring inbox/outbox |
| L | inbox `seen()`/`entry_count()` returned stale answers in multi-process use | both re-fold on stat change |
| — | no test exercised the whole pipeline end to end | `tests/test_delivery_integration.py`: mesh, hub, and file-bundle pipelines with ACK-terminal delivery and the hostile paths |

Round 2 had fixed 8 defects (A–H, table above); round 1 fixed journal-first
ordering, journal size caps, expired-enqueue rejection, and an in-function
import.

Round 11 (whole-stage adversarial review of every fix) found the last
design-level defect in the delivery layer:

| # | Item | Fix |
|---|---|---|
| BB-p | the inbox replay-cache journal grew monotonically (accepted + evicted pairs); past the 16 MiB cap the inbox bricked itself forever with `DeliveryInboxCacheCorrupt` and no recovery path | lossless auto-compaction: fold → rewrite live entries under the cross-process lock, on both the load path and the append path; corruption still fails closed (pinned by raw tests) |

Also swept with no findings: conformance vector regeneration is byte-idempotent,
`__all__` exports complete, no patch-script debris (double docstrings, dead
attributes), and the three per-module re-fold implementations are
semantically equivalent.

Round 10 (design/execution/security/maintainability review of Slice B)
found and fixed 2 design-level findings:

| # | Item | Fix |
|---|---|---|
| BB-n | a spawn failure (missing interpreter, fd/memory exhaustion) escaped `run()` as a raw `OSError` | wrapped — surfaces as a **retryable** `AdapterHookRejected` |
| BB-o | `AdapterHookRejected` conflated transient failures (timeout, crash, spawn) with permanent ones (digest mismatch, protocol violations) — outbox-style callers could not decide on retries | the exception now carries `retryable`; timeout/crash/spawn are retryable, everything else permanent |

Maintainability notes carried as documented boundaries rather than fixes:
the local runner is Python-artifact-only in v1 (`python -I`), disabled by
default, and requires an explicit unsafe-local-execution opt-in. The separate
process, timeout, and bounded stdio are operational controls, not an OS or
capability sandbox; untrusted artifacts require a separately sandboxed
executor.

Upstream note (pre-existing, unrelated to this PR): the live-HTTP harness
in `test_trade_rule_agreement.py` acquires ports with a bind(0)-close-
rebind race (`_free_tcp_port`) and polls `server.started`, which flakes
intermittently (~1 in 4 file-scoped runs, never in a full-suite run, on
code with and without this PR's changes). A bind-and-hold socket handed to
uvicorn would close it.

Round 9 (full-test hunt on the Slice-B runtime) found and fixed 2
contract-escape bugs, both of the same family as Phase-0 bug A; each has a
pinned test:

| # | Defect | Fix |
|---|---|---|
| BB-i | `input_payload` containing `NaN`/`Infinity` passes `json.loads` but explodes `canonical_json` with a raw `TypeError`, escaping the `AdapterHookRejected` contract | canonicalization wrapped — contract type restored |
| BB-m | an adapter returning a float (or printing `NaN`) in its result hit the same raw `TypeError` at result serialization | same wrap on the result path |

Also pinned: eight concurrent `run()` calls stay independent, CRLF-line
adapters parse, a silent `exit(0)` adapter with no protocol lines fails
closed, and NaN-class inputs are refused before any subprocess spawns.

Round 8 (independent programming review of the cumulative fixes) found and
fixed 4 items; each has a pinned test or a documented rationale:

| # | Item | Fix |
|---|---|---|
| AJ | ingest `Content-Length: ²` — unicode `isdigit()` chars pass `isdigit()` but explode `int()`, killing the handler thread (log-spam DoS) | strict ASCII-digit check → clean 400 (raw-socket pinned) |
| AB | `_EnvelopeChannel.MAX_CONTENT_LENGTH` dead attribute implied truncation exists | removed |
| AD | gossip loop teardown left the boot task "destroyed but pending" | boot task cancelled and drained on the loop before `close()` |
| AF | flood drops on the gossip inbound queue were silent | observable `dropped_inbound` counter |
| AA | deliberate design note added: the TTL *window* is the receiver's inbox decision — sender-side clock checks would break deterministic replay | documented in both real transports' `send()` |

Round 7 (full review of the Phase-1 deliverables) hardened the adapters
further; every item has a pinned test:

| # | Item | Fix |
|---|---|---|
| — | shim-channel signature interop was untested | pinned: shim-signed messages verify through gossip's own `_verify_msg_signature` with the same payload shape as `TeamChannel.send` |
| — | hostile deeply-nested gossip content could raise `RecursionError` out of the receive callback | caught with the other malformed-content paths |
| — | `GossipNode.direct_message` would `AttributeError` on the shim channel | shim `dm` routes to send with a DM scope |
| — | duplicate port bind raised the borrowed layer's raw `ValueError` | construction wrapped — lifecycle errors are uniformly `GossipTransportError` |
| — | both real transports broadcast/POSTed envelopes WITHOUT client-side signature validation, unlike the file-bundle transport | `validate_envelope` runs before any wire I/O in `send()` (before the peer-count check, so error names the real problem) |

Round 6 (adversarial review of the Phase-1 adapters as submitted) found and
fixed 3 defects; each has a pinned regression test:

| # | Defect | Fix |
|---|---|---|
| W | gossip `send()` checked `peer_count` only BEFORE broadcasting — peers disconnecting inside the send window produced a false accept (nothing delivered, outbox would never retry) | post-broadcast peer re-check: an empty peer table after the send is an honest `no-connected-peers` failure |
| X | `no_proxy` loopback bypass used `setdefault` — a user with an existing `no_proxy` lacking loopback entries stayed broken through their system proxy | loopback entries are merged into any existing value, idempotently |
| Y | federation `verify_tls=False` built a fresh unverified SSL context on every POST | context built once per process |

Round 5 (Phase-1 review) found and fixed 2 defects in the new adapters plus
one borrowed-layer latent bug:

| # | Defect | Fix |
|---|---|---|
| U | `WebSocketGossipTransport` restart left the startup event set and a stale `_start_error`, so a second `start()` returned before the new node had bound its port | startup event/error reset in `start()`; failure paths shut the loop thread down |
| V | `WebSocketGossipTransport.start()` returned `GossipNode.url` — the constructor-valued property (`ws://host:0` under ephemeral ports) instead of the bound URL | adapter returns the URL captured from `start()`; `GossipNode` now records the bound-port URL in `start()` and its `url` property reports it |
| — | macOS/Windows system proxies intercept loopback WebSockets (503 through the proxy) | adapter `start()` sets `no_proxy` for loopback via `setdefault`, honouring pre-existing user configuration |

## Remaining Boundaries

The current Nostr tier is public-only. Private payload encryption, BLE, sealed
courier transport, and cross-node claim semantics remain outside delivery v1.
Network adapters that still expose only the low-level `Transport` ABC must be
wrapped as governed plugin providers before they are enabled by default.

# Changelog

All notable changes to **NTH DAO** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Nostr adapter core (Phase 2, segment N1): `nth_dao/nostr/` wraps the
  maintained `nostr-sdk` binding (optional extra `nth-dao[nostr]`) for the
  internet relay tier. NTH Ed25519 identities sign NostrKeyBinding documents
  asserting secp256k1 key ownership (design doc §6.3); delivery envelopes
  travel as kind-30078 (NIP-78) events whose content is the canonical
  envelope JSON and whose `d` tag pins the message_id. Receipt-side
  verification is two-tier (nostr-sdk checks the relay-tier event
  signature, the delivery layer re-validates the envelope author signature)
  and fails closed on tamper, wrong kind, unsigned envelopes, d-tag
  addressing mismatches, and non-integer timestamps (the timestamp is
  actually applied — deterministic event ids are pinned by tests).
- Nostr relay client (Phase 2 N2) and delivery transport (N3):
  `NostrRelayClient` wraps the borrowed async `nostr_sdk.Client` on a
  background loop thread (same bridge as the gossip adapter) with publish
  (relay-OK bounded wait) and kind-filtered subscription delivery;
  `NostrTransport` plugs the public relay tier into the delivery router
  (broadcast, PRIVACY_PUBLIC_RELAY, external_infrastructure) with
  fail-closed envelope re-validation. Tested against an in-process fake
  NIP-01 relay (`tests/fake_nostr_relay.py`): publish round-trip, hostile
  relay rejection, private-tier refusal, relay URL policy, and long-lived
  subscription delivery.

- Trade adapter runtime (Slice B): `nth_dao/trade_rules/adapter_runtime.py`
  executes an approved, digest-pinned adapter artifact as a bounded
  subprocess speaking `nth-trade-adapter-rpc/1` — a minimal MCP-shaped
  JSON-lines stdio protocol (digest handshake, hook invocation, result).
  It is disabled by default. Explicitly enabled reviewed artifacts run with
  bounded wall time, concurrency, and stdio plus pre-spawn digest
  verification. These are operational controls, not a security sandbox;
  CPU, memory, filesystem, network, and subprocess capabilities require an
  external sandbox. Protocol violations fail closed.

- Phase 1 real transports for the delivery layer: `WebSocketGossipTransport`
  wraps the existing signed P2P `GossipNode` as a synchronous delivery
  Transport (background loop bridge, node-signed gossip messages carrying
  author-signed envelopes, trusted-pubkey passthrough, `TeamChannel`
  truncation bypassed via a signing shim channel), and
  `FederationTransport` + stdlib `FederationIngestServer` push signed
  envelopes to known peers over bounded HTTPS/loopback HTTP (strict URL
  policy, capped responses, no redirects, concurrency gate, Content-Length
  bounds with a bounded 413 drain). ACKs travel back as `delivery.ack`
  envelopes unwrapped by `ack_from_envelope` (author must be the ACK
  receiver). End-to-end integration tests run the full
  outbox → router → real wire → inbox → signed-ACK-return → delivered flow
  for both transports, plus router policy selection and gossip→federation
  fallback. Tests include signature interop, raw-socket hostile
  Content-Length and client-side validation pins. `GossipNode.start()` now
  reports the actual bound port when constructed with `port=0`.

- Delivery layer Phase 0 (`nth_dao/delivery/`), the transport-agnostic signed
  envelope spine: `TransportEnvelope v1`, signed receiver ACKs, crash-safe
  bounded outbox/inbox journals, policy routing, and loopback, file-bundle,
  HTTPS federation, WebSocket gossip, and public Nostr adapters. Forwarded ACK
  digests are accepted only for valid hop-count mutations. `PluginDeliveryRuntime`
  is the durable bridge to the Host-governed transport capability and persists
  a complete leased batch before acknowledging its provider. Ten fixed
  `delivery_envelope_v1` and `delivery_ack_v1` conformance vectors cover wire
  bytes, content binding, signatures, time, version, and tamper failures.

- A Host-only, immutable Intent acceptance policy snapshot that binds one exact
  reviewed draft to direct member DIDs, roles, monotonic revocations,
  membership/revocation source digests, solver classes, automation ceilings,
  policy lineage, validity, and strict size limits. New acceptance contexts
  retain its content digest under the existing journal/audit chain; legacy rows
  remain readable but explicitly unbound. A bounded append-only local policy
  store retains canonical snapshots, enforces contiguous monotonic-revocation
  lineage, and serializes current-head changes with governed acceptance under a
  shared cross-process lock. The journal's clock now drives both policy and
  envelope validation and rechecks both at insertion; legacy callbacks cannot
  fabricate governed provenance. Policy records now have a migratable audit hash
  chain, externally pinnable tail and cumulative payload accounting. Governed
  history verification rejects foreign workspaces and missing policy evidence;
  indexed head/digest operations avoid reparsing the full history. Separate
  Python/Node policy vectors cover canonical bytes, digests, strict prime-order
  Ed25519 DIDs, resolution, and successor rules. No REST/UI, solver,
  delegation, business promotion, payment, or execution path is enabled.
- A language-neutral `market.index` v1 plugin contract and a bounded,
  principal-isolated in-memory reference provider. Entries are canonical,
  content-addressed search projections that retain exact source protocol,
  object, publisher, digest, and locator bindings; they never become listing
  or execution authority. Mutations use content-digest CAS, identical retries
  are idempotent, and five-minute HMAC-authenticated cursors bind principal,
  normalized query, revision, snapshot time, and stable rank position. Expired
  entries remain available for a bounded stale-audit window and are then
  reclaimed with cursor invalidation and quota recovery. Wire compatibility,
  non-authoritative protocol compatibility, and Host effect authorization are
  separate checks, so a network index cannot inherit the local provider's
  no-effect profile. The provider is installed disabled
  and does not replace or dual-write the existing Market stores or REST path.
  Checked-in schemas and wire vectors include an independent Node.js canonical
  hash check. Settlement and real-funds execution remain disabled.
- A language-neutral `nth-dao-plugin-rpc` v1 subprocess boundary for statically
  reviewed local workers. It copies each entry artifact from one verified read
  stream into a private workspace-local per-generation snapshot and executes
  that snapshot, binds the resolved launcher path and bytes into lifecycle
  audit, and clears prior grants whenever that profile changes. Explicit
  environment values never enter a deterministic audit commitment and require
  fresh authorization after launch-spec reconstruction. Cross-process snapshot
  leases protect active workers; registration removes and audits only inactive
  Host-owned generations, while cleanup failures remain visible and retryable.
  It uses an exact nonce-bound handshake and Host-generated invocation IDs,
  uses RFC 8785-compatible key ordering and cross-language safe integers,
  limits canonical JSON frames and stderr, starts with a minimal explicit
  environment, interrupts blocked calls during disable, and revokes the whole
  provider generation on timeout, crash, idle exit, or protocol corruption.
  Requests that cannot be represented by the RPC JSON subset or fit the
  configured worker frame are rejected before pipe I/O without quarantining a
  healthy worker.
  Worker retry hints cannot override an `at-most-once` or `fail-closed`
  capability contract. Process-group
  cleanup is best effort until a platform job/container boundary exists. Checked-in
  canonical vectors cover handshake, invocation, result, error, shutdown, and
  non-BMP cross-language key ordering, with a real Node.js conformance test.
  This is process supervision, not an OS sandbox or third-party package loader;
  CPU/memory quotas and authoritative descendant containment still require a
  platform Job Object, cgroup/container, or WASI runtime, and irreversible
  capabilities remain disabled.
- Authenticated network retrieval of one exact missing Trade Dispute Statement:
  a short-lived bilateral DID-signed Fetch Request reaches a rate-limited public
  responder backed by an atomic replay journal and signed Spine disclosure
  audit. The console requester DNS-pins the peer, verifies a challenged identity
  card against `responder_did`, and independently replays the signed Response
  and standalone signed audit binding. A bounded durable requester outbox keeps
  the exact signed Request across retries, advances generation only after signed
  expiry, and retains a verified Response and audit before returning success, so
  an exact result can be replayed after restart without another network call.
  The public responder verifies the signed envelope before loading retained
  trade context and gives the same unavailable response for missing and
  unauthorized context. Fetch remains non-importing; the audit event does not
  prove remote chain inclusion, and the Statement does not prove its claim true.
- Signed Rule Recognition Proof Page v2 federation for graphs beyond the v1
  256-statement ceiling, with independently signed 256 KiB pages, a 64 MiB
  page-set bound, shared observation/statement/head commitments, DNS-pinned
  deadline-bounded retrieval, legacy-first import fallback, crash-safe batched
  CAS/Spine completion, semantic refresh deduplication, exact evidence repair,
  authenticated import status, and deterministic positive/negative conformance
  vectors. Page import audit v2 fails closed on missing, duplicate, mixed, or
  commitment-inconsistent page sets and grants no trust or execution authority.
- Verified Trade Offer v2 federation discovery through a short-lived signed
  exchange hint, a bounded content-addressed head-proof bundle, complete
  disclosed revision-chain verification, canonical active-head publication,
  positive and negative conformance vectors, read-only
  market projection, 24-hour maximum discovery lifetime, bounded public reads,
  and non-claimable UI presentation. Discovery proves the publisher's signed
  claim; it does not prove availability, create an Agreement, or authorize
  settlement.
- Authenticated, read-time-reverified inspection of exact remote Trade Offer
  terms retained in the volatile federation cache, including concrete exchange
  legs, Rule references, verification state, and recent-source evidence in the
  Tasks UI. Exact pull-set checks reject omitted or duplicate records; read-time
  TTL pruning, per-peer/global/byte capacity limits, and a digest index prevent
  false freshness and unbounded full-cache inspection. Cached documents remain
  read-only, non-actionable, and non-durable across restart or stale eviction.
- Explicit durable retention of every revision in a reverified remote Trade
  Offer head proof as a signed claim in the local append-only Offer Store. The Console-authenticated import
  is exact-digest, cross-process serialized, idempotent, provenance-bound, and
  anchored to the signed Spine. A signed `trade.offer.import.proposed` event
  retains the complete disclosed revision chain and discovery evidence before
  Store mutation, so
  restart recovery does not depend on the volatile federation cache; a later
  `trade.offer.imported` event completes the Store anchor idempotently, including
  across node-key rotation. The Spine anchor retains and independently
  reparses and reverifies the proposal's complete signed Offer against both its
  digest and the persisted Store bytes, plus the exact signed discovery
  announcement, federation key, source DID, and observation provenance after
  volatile cache eviction. Malformed digests are rejected before lock-path or
  cache access. Reads fail
  closed if Store and Spine diverge, while a content-digest-backed cross-log
  fingerprint detects same-size/re-timestamped disk changes without replaying
  every Ed25519 signature on an unchanged log. The Tasks UI exposes this
  as **Save locally** and states that persistence grants no trust, acceptance,
  reservation, or execution authority.
- Signed Trade Rule Recognition v1 chains for community, DAO, or individual
  recognition, deprecation, and revocation of exact Rule Package digests,
  including mandatory bounded expiry, issuer Rule-ID scopes, local observed
  quorum projection, content-addressed persistence, metadata-only invalid-input
  quarantine, and TypeScript verification vectors. Recognition never grants
  executable or funds authority automatically and does not claim globally
  fresh revocation.
- Recoverable Rule Recognition audit projection that persists the exact signed
  statement in local CAS before appending an idempotent
  `trade.rule.recognition.recorded` Spine event. Package-scoped reconciliation
  repairs interrupted anchors, and cross-log verification rejects missing,
  duplicate, conflicting, or orphaned local facts. Formal Web v2 endpoints
  remain fail-closed when the signed Spine is unavailable, expose bounded
  reconciliation diagnostics, and reject rollback evidence before new CAS
  writes.
- Signed local Recognition trust-policy v1 revisions with node-bound genesis,
  predecessor-authorized controller rotation, canonical content-addressed
  storage, durable rollback-detecting head, recoverable idempotent
  `trade.rule.recognition.policy.updated` Spine anchors, bounded sensitive Web
  v2 history/reconciliation, and time-pinned advisory Rule Package evaluation.
  Deterministic public vectors and schemas cover the policy wire format,
  delegated successor, audit payload, and correctly signed unauthorized-chain
  attacks. Recognition quorum still never grants execution authority.
- Recognition policy hardening: local-console-only governance mutations reject
  arbitrary self-signed CapTokens, persistent cross-process throttling bounds
  writes and reconciliation, HTTP failures no longer expose local paths,
  historical evaluation selects the policy effective at the requested time,
  authorized key rotation preserves the signed genesis namespace, and audit
  payloads cryptographically bind `policy_id` to `node_did`.
- Recoverable Trade Order audit outbox with `prepared -> cached -> anchored`
  state transitions and exact, idempotent `trade.order.accepted` Spine events.
- Execution-readiness verification that reloads and resolves every transitive
  Trade Rule dependency under both signed party policies and the executor's
  current local policy.
- Signed Trade Execution Receipt v1 claims that bind an accepted Order,
  bilateral operation grant, Rule Hook and schemas, execution-readiness
  snapshot, current executor policy, content-addressed Adapter descriptor and
  artifact, stable operation-scoped execution identity, result, and evidence without
  enabling payment or settlement side effects.
- Cross-process Trade Execution Receipt CAS storage that returns byte-identical
  retries, retains contradictory signed candidates, and leaves a durable
  fail-closed conflict marker when capacity prevents full retention.
- Mandatory `TradeExecutionCoordinator` issuance through that CAS, plus public
  conflict status that distinguishes complete retention from marker-only loss.
- Recoverable Trade Execution audit records that prepare before Receipt CAS,
  project exact idempotent `trade.execution.recorded` events into the signed
  Spine, verify established anchors and blocked conflict evidence on replay,
  survive wall-clock rollback, and page every audit state under one limit.
- Content resolver and optional JSON Schema 2020-12 validation for exact
  operation input and result bytes at both signing and receiver verification.
- Hook-scoped Adapter permissions bounded by each Rule Manifest's declared
  execution permissions, preventing dependency permissions from leaking into
  unrelated Hook execution.
- Public Execution Adapter and execution-audit payload schemas, plus
  deterministic positive/negative conformance vectors that reconstruct Rule
  Packages, policies, Adapter artifacts, execution content, readiness,
  Receipt verification, and its signed Spine projection.
- Counterparty-signed Trade Receipt Review v1 with mandatory independent
  policy replay, exact Order/Receipt/policy binding, negative reason codes,
  conflict-retaining CAS persistence, and recoverable idempotent
  `trade.receipt.reviewed` Spine projection.
- Receipt Review and Spine payload schemas plus deterministic positive and
  negative conformance vectors.
- Receipt Review write-ahead audit records that recover normal and conflicting
  Spine projections after restart without object resubmission, plus explicit
  idempotent `trade.receipt.review.conflicted` events.
- Signed Receipt Review Delivery/Acknowledgement federation with exact reviewer
  policy snapshots, destination and TTL binding, receiver-side policy replay,
  durable restart-safe sender dispatch, expiry-only renewal history, bounded
  public intake, deterministic positive/negative vectors, and an Orders UI
  workbench that labels Reviews and peer ACKs as claims rather than facts.
- Receipt Review audit outbox v3 retains the exact Rule and Adapter Policy
  snapshots used at signing or intake, rejects tampering on every read, safely
  upgrades digest-compatible v1/v2 records, and stores an immutable first local
  observation time separately from mutable workflow timestamps so delivery is
  reproducible across process restarts and later local policy rotation.
- Receipt Review ACKs now bind the durable first receiver observation time,
  reject retries aimed at a different peer, account for crash residue in all
  outbox capacity projections, and expose retained conflict digests in the UI.
- Signed, content-addressed Trade Dispute Statement v1 claims bound to one
  disputed Receipt Review case, exact Review candidate, Execution Receipt, and
  accepted Order. The bounded append-only DAG format separates typed response
  or remedy claims from supporting evidence, caps declared content, and supports
  exact Package/hook-version selectors that fail closed without a resolver. A
  distinct unresolved transport type prevents callers from treating an
  unresolved Rule dependency as a fully verified statement. The WebCrypto
  conformance implementation checks semantic artifact/role/time/resource
  bindings in addition to source signatures. A strict schema and deterministic
  positive, clock-boundary, signature-tamper,
  correctly signed future-time, and Review-rebinding vectors are included.
  Statements do not prove a claim true, resolve a dispute, authorize settlement,
  or execute a Rule hook.
- Bounded, cross-process Trade Dispute Statement CAS retention with strict
  content-address validation, crash-residue tolerance, deterministic paging,
  exact-context re-verification, and explicit reconciliation diagnostics.
  Idempotent `trade.dispute.statement.retained` Spine anchors bind the complete
  signed claim digest and are permanently labelled
  `signed-claim-not-adjudicated`; failed Spine writes remain recoverable from
  the retained statement without weakening time or Rule Package validation.
- Destination-bound Trade Dispute Statement Delivery and receiver-signed
  Acknowledgement v1 envelopes, with exact Order/Receipt/Review/Statement
  bindings, bounded TTL and nonce, deterministic positive and tamper vectors,
  and an explicit `retained-claim-not-adjudicated` status. Receiver intake
  rejects matching Spine anchors signed by any DID other than the receiver.
- Restart-safe, bounded Trade Dispute Statement intake journal with exact first
  observation time, observed-to-anchored-to-acknowledged recovery, typed
  canonical artifacts, SQLite cross-process serialization, and fail-closed
  journal integrity checks. Intake persists before Package resolution and may
  resume an exact previously observed Delivery after transport expiry.
- Dispute intake first-observation time is now a receiver-signed canonical
  attestation bound to the exact Delivery digest and recipient. Unsigned legacy
  rows fail closed; acknowledged rows can move to a verified archive and are
  purgeable only after the maximum transport window and explicit retention.
  Both hot and archive storage have restart-enforced record and byte ceilings;
  authenticated new deliveries run bounded purge-then-archive maintenance, and
  noncanonical Observation bytes are rejected on every journal read.
- Spine append uses a signed, chain-bound write-ahead intent. Exact crash tails
  recover without accepting arbitrary truncation; missing, foreign-signed, or
  byte-conflicting intents remain corrupt. Ambiguous I/O raises a typed outcome
  containing the exact event ID, and `reconcile_append` recovers or disproves
  that event before retry. Dispute Statement and transport clock-skew policy
  values are capped consistently at 86,400 seconds in Python and TypeScript.
- TypeScript dispute verifiers require an immutable artifact bundle minted only
  after the constructor internally validates the signed Offer, Proposal,
  Acceptance, Order, Execution Receipt, and Receipt Review. Callers cannot
  supply replacement validators. Store paging caches verified content-addressed
  headers while retaining per-file digest checks and full validation of every
  selected statement.
- Canonical Trade Execution Adapter Policy v1 objects with a public wire
  schema and digest shared by Receipt Review and conformance implementations.

### Fixed

- Local Dispute Statement creation now holds a workspace-scoped,
  cross-process single-flight lease for the complete idempotent operation.
  Concurrent retries with the same Order, Receipt, Review, and idempotency key
  wait for and reuse one durable result instead of redundantly contending on
  Rule resolution, Store, Outbox, and Spine locks and returning false 503s.
  Conflicting content still returns 409, and lease timeout remains an explicit
  retryable 503.
- Spine verified-read caches now bind invalidation tokens to the complete log
  content, detecting same-size tampering even when filesystem timestamps are
  restored. Requester Fetch outbox updates reject timestamp regression before
  commit, and a late concurrent failure can no longer overwrite a completed
  verified response with stale failure state.
- Spine append now serializes across processes, refreshes the chain head under
  lock, validates the complete chain before writing, and rejects oversized or
  structurally ambiguous events.
- Spine consumers can obtain a lock-consistent verified snapshot, while
  semantic append performs uniqueness checks and writes under the same process
  lock so concurrent writers cannot create an unverified read window.
- Order audit retries no longer trust a mutable `anchored` status file and can
  restore a rolled-back CAS cache from the write-ahead signed Order.
- Trade Receipt timestamps no longer accept or reattach precision beyond
  Python's microsecond clock.
- Receipt Review conflicts are isolated by semantic Review ID, marker-only
  evidence can be completed after capacity increases, self-referential markers
  are not reported complete, and partial Receipt/Order digest binding is
  rejected.
- Order, Execution Receipt, and Receipt Review acknowledgements now apply the
  configured clock-skew allowance symmetrically at both edges of a signed
  delivery lifetime, so a receiver clock slightly behind the sender no longer
  causes an otherwise valid durable intake to fail.

## [0.10.0b1] - 2026-06-07 - Beta release: signed mandates, A2A server, hardened collaboration runtime

This beta is the first v0.10 preview. It is intended for testers and
early integrators, not yet for a stable production deployment.

### Added

- Signed mandate primitives: `IntentMandate`, `CartMandate`, and
  `PaymentMandate`, with Data Integrity style proof helpers and
  conformance vectors.
- Mandate EventBus event builders and a web console mandate sidebar.
- A2A boundary server and Agent Card helpers for JSON-RPC style task
  lookup and capability discovery.
- Hardened action routing with explicit pubkey lookup, signed request /
  response handling, TTL and persistent nonce replay protection.
- EventBus correction events, event subscriptions, and fault isolation
  integration with signed audit events.
- Agent daemon support for background group-channel polling and replies.
- Browser-side Ed25519 wallet helper and frontend Vitest coverage for
  mandate UI verification.

### Fixed

- Canonical JSON and identity signing audit gaps, including stricter
  numeric handling and key consistency checks.
- Safer append-only JSONL writes and lock-timeout behavior for
  concurrent local-first operation.
- Web rate limiting and timing-floor behavior around sensitive mandate
  store routes.
- Packaging now includes newly added `nth_dao.mandate` modules and the
  required `team_layer` runtime packages.

### Validation

- Python test suite: 1067 passed, 11 skipped.
- Frontend Vitest suite: 2 passed.
- Frontend production build: passed.
- Pre-release secret/runtime scan: required before every commit, push,
  and release.

## [0.9.6] - 2026-06-02 - Unique group names, governance votes, chat-native collaboration UI

User-facing layer: workspace-unique groups with policy votes, plus the
TS panels for consumer chat app-inspired "find / add / nearby / group" UX. No
breaking changes to existing protocol artifacts.

### Added - GroupRegistry (Python, protocol)

- `nth_dao/group_registry.py` - workspace-unique groups.
  - `normalize_group_name(name)` produces a stable slug
    (`Frontend Team!` -> `frontend-team`).
  - `GroupRecord` is signed by the founder; subsequent updates re-sign.
  - `GroupPolicy` enum: `open` / `approval` / `closed` / `voted`.
  - `GroupRegistry.publish()` enforces slug uniqueness - same group_id
    re-publish updates; different group_id reusing the slug raises
    `GroupRegistryError`.
  - `search()` is fuzzy-match across slug / display_name / description.
- **Governance voting** - `PolicyChangeProposal`, signed by a member.
  Members append signed `Vote` records; `resolve_proposal` returns
  passed/reason. Threshold: `> 50%` of current member pubkeys, deduped.
  `apply_proposal` builds a new GroupRecord re-signed by an admin.
- Anti-DoS: non-member proposer rejected; duplicate yes-votes from same
  pubkey deduped; tampered proposer signatures rejected.

### Added - Web API (Python, FastAPI)

In `nth_dao/web/`, 14 new endpoints:

- `GET  /api/agents/search?q=` - chat-native fuzzy search over
  `PeerFinder` (matches agent_id, label from registry metadata,
  capabilities, groups; ranked).
- `POST /api/agents/lan_discover` - server-initiated UDP LAN scan,
  returns LANPeers with `ws_url` and `pubkey_hex`.
- `POST /api/agents/add` - add an agent by `target_agent_id` OR
  `target_did` (W3C did:key resolved server-side).
- `POST /api/groups/registry` - prepare unsigned group skeleton.
- `POST /api/groups/registry/publish` - persist a signed GroupRecord.
- `GET  /api/groups/registry` - list all.
- `POST /api/groups/registry/search` - fuzzy search.
- `POST /api/groups/registry/{group_id}/proposals` - prepare unsigned
  proposal skeleton.
- `POST /api/groups/registry/{group_id}/proposals/publish` - submit a
  signed proposal.
- `GET  /api/groups/registry/{group_id}/proposals` - list proposals
  with resolution status.
- `POST /api/groups/registry/{group_id}/proposals/{proposal_id}/sign_vote`
  - append a signed vote and re-resolve.

All write endpoints follow the same "server prepares unsigned skeleton ->
client signs locally -> client posts back" pattern so private keys never
touch the wire.

### Added - TS panels (frontend/src/panels/, per the iron rule)

Four consumer chat app-inspired React panels + a shell that ties them together:

- `ContactsPanel` - search by name/label/capability, "+ Add" buttons,
  fallback "exact agent_id / DID" form.
- `NearbyPanel` - "people nearby" LAN discovery, with optional PSK.
- `GroupsPanel` - list / search / create unique groups. Shows policy
  color band per group; the "create" form lets the user pick the
  initial policy.
- `GovernancePanel` - propose a policy change with rationale; vote
  yes/no/abstain on open proposals.
- `ContactShell` - top tab bar with the four panels, browse-only mode
  when no wallet is connected.
- `chat-panels.css` - standalone styles so existing `styles.css` is
  untouched.

The host app supplies `actorPubkeyHex` and `sign(payload)` (browser
wallet of any flavor). When omitted, the panels render but signing-
required actions are disabled and labeled.

### Tests

- 238 passing + 5 skipped (was 217 + 5).
- 21 new tests in `tests/test_v096_group_registry_and_web.py`:
  slug normalization, slug-collision rejection, search ranking,
  proposal pass/fail with majority/below-threshold, non-member
  proposer rejection, double-yes dedup, tampered proposer sig
  rejection; plus a FastAPI TestClient pass over each new endpoint.

### No protocol changes on disk

`Mission`, `MissionTemplate`, `TeamConfig`, `GuardianSet`, `Endorsement`,
`Invitation`, gossip envelope - all unchanged. GroupRecord is a brand-new
artifact stored under `team_groups/` next to existing files.

## [0.9.5] - 2026-05-31 - DID:key, AgentLedger, Guardian recovery, A2A boundary

Five additive deliverables, no breaking changes. v0.9.4 artifacts load
byte-identically.

### Added - W3C did:key standard alignment

- `nth_dao/did_key.py` - pure-stdlib base58btc + multicodec (0xed 0x01)
  encode/decode of Ed25519 pubkeys per W3C did:key spec.
- `AgentIdentity.as_did()` - emits a full `did:key:z...` string. Replaces
  the v0.9.3 simplified placeholder.
- `AgentIdentity.from_did(did)` - rebuilds a verify-only identity from
  a DID. Useful for trusting a peer by their DID without their private key.
- `MissionTemplate.publisher_did` is now a real did:key (previously
  a truncated-hex placeholder).

### Added - AgentLedger persistence

- `nth_dao/agent_ledger.py` - per-pubkey-fingerprint append-only event
  ledger. Stored at `sidechain/agents/<fp>/{profile.json, ledger.jsonl,
  stats.json}`. Same anti-Sybil pattern as reputation credits: one
  pubkey = one ledger regardless of how many agent_ids it uses.
- Event types: step claim / complete / failed, handoff (given +
  received), review given / received, endorsement given / received,
  mission owned.
- Deterministic reducer (`compute_stats`) folds events into
  `{missions_owned, steps_completed, success_rate, handoffs_*,
  templates_used, categories, total_token_cost, last_active_at}`.
  A Rust/Go port walking the same JSONL produces the same dict.
- Events are signed when a crypto identity is available; unsigned
  events still count (best-effort signing per Sec model).

### Added - Guardian-based social recovery

- `nth_dao/guardian.py` - N-of-M threshold recovery. The agent publishes
  a signed `GuardianSet(guardian_pubkeys, threshold)`. To replace a key,
  the agent assembles a `KeyReplacementProof` and collects M guardian
  signatures over its canonical payload.
- `verify_replacement(proof, guardian_set)` validates:
  - guardian_set itself signed by the protected pubkey,
  - proof references the right set_id + fingerprint,
  - >= threshold distinct valid signatures from guardian pubkeys.
- `GuardianStore` persists sets + proofs under `team_recovery/` and
  maintains `active_replacements.json` for `resolve_current_pubkey(fp)`
  queries. Other components can use that to follow key rotations.
- The protected pubkey MUST NOT appear in its own guardian set;
  duplicate signatures de-duplicated; mallory's signature ignored
  when she isn't in the set.

### Added - A2A boundary translation primitives

- `nth_dao/a2a/translate.py` - pure data transformations between our
  types and Google Agent2Agent (A2A) shapes.
- `template_to_a2a_skill(template)` - render a MissionTemplate as an
  A2A Skill (with JSON-Schema input/output specs derived from IOField).
- `agent_card_from(...)` - assemble an A2A AgentCard JSON dict
  suitable for `/.well-known/agent.json`.
- `a2a_task_from_mission(mission)` - render a Mission as an A2A Task
  (status mapped: planning -> submitted, active -> in_progress, ...).
- `mission_inputs_from_a2a_message(message, template)` - extract +
  validate structured inputs from an A2A SendMessage payload.
- **No HTTP / no JSON-RPC**: those land in a separate package
  (`nth-dao-a2a-adapter`, v0.10.0). The protocol core stays stdlib-only.

### Added - wire-format conformance vectors expanded

- `nth_dao/conformance/vectors.json` grew from 22 vectors / 6 categories
  to **31 vectors / 11 categories**.
- New categories: `channel_message_canonical` (2),
  `invitation_canonical` (1), `team_config_canonical` (1),
  `did_key_encoding` (3), `lan_psk_tag` (2).
- A non-Python implementation passing all 31 vectors is now wire-compatible
  for the full Layer 1-2 protocol surface (modulo replay-window timing).

### Tests

- 217 passing + 5 skipped (was 169 + 1). +48 new tests:
  - `tests/test_did_key.py` - 16 (round-trip, error paths, AgentIdentity
    integration, template.publisher_did upgrade).
  - `tests/test_v095_features.py` - 25 (AgentLedger fold, scoping,
    handoff counters, Guardian set / replacement valid + below-threshold
    + non-guardian + duplicate + tampered, GuardianStore commit /
    resolve, A2A skill / card / task / inputs).
  - Conformance vectors: 5 -> 5 (test count unchanged but covers 31 vectors).
- All 169 v0.9.4 tests still pass; no behavior regression.

### No protocol changes on disk

`Mission`, `MissionTemplate`, `TeamConfig`, `Endorsement`, `Invitation`,
gossip envelope - all unchanged. The `publisher_did` field that already
existed since v0.9.3 just contains a more useful value now.

## [0.9.4] - 2026-05-31 - Sustainability sprint

This release does NOT add new protocol surface. It fills six holes the
v0.9.1 code review identified as preventing the project from outliving its
single maintainer:

### Added - SECURITY.md + key recovery

- `SECURITY.md` - supported versions, disclosure address, threat model
  (what we defend against + what we explicitly don't), per-vulnerability
  history.
- `nth_dao/key_recovery.py` - passphrase-protected `RecoveryKit` for
  exporting / re-importing an `AgentIdentity`. Uses libsodium
  `crypto_secretbox` (XSalsa20 + Poly1305) with Argon2id key derivation
  at INTERACTIVE difficulty (~0.5s per try). Rejects tampered kits;
  rejects wrong passwords without revealing whether the kit format itself
  is valid.
- 14 tests in `tests/test_key_recovery.py`.

### Added - docs/MIGRATIONS.md + migration test runner

- `docs/MIGRATIONS.md` - forward-compat policy for 0.9.x, per-version
  delta, contributor rule that all new fields default-init safely.
- `tests/test_migrations.py` + `tests/migration_fixtures/0.9.0/`
  fixtures - a v0.9.0 mission and team.json file. The runner asserts
  current code parses them cleanly and preserves the originally-set
  fields. Unknown fields are tolerated.
- 4 tests confirm round-trip integrity through the current code.

### Added - nth-status + nth-metrics CLI

- `nth_dao/cli/status.py` - text or JSON snapshot of a workspace.
  Sections: version, team, agents (alive vs registered), missions
  (by status + archived count), templates (total + deprecated +
  reviews), trust (anchors, endorsements, revocations).
- `nth_dao/cli/metrics.py` - Prometheus exposition-format `/metrics`
  endpoint, served by the stdlib `ThreadingHTTPServer`. Each metric is
  a gauge with HELP + TYPE comments. Includes `/healthz`. Pure stdlib -
  no `prometheus_client` dependency.
- New console scripts: `nth-status`, `nth-metrics`.
- 12 tests in `tests/test_cli_status_metrics.py` including a smoke test
  that actually starts the HTTP server, scrapes it, and shuts it down.

### Added - requirements.lock files

- `requirements/README.md` - reproducibility rationale + usage.
- `requirements/base.txt` (empty - core is stdlib only).
- `requirements/crypto.lock.txt`, `requirements/ux.lock.txt`,
  `requirements/web.lock.txt`, `requirements/dev.lock.txt` - pinned
  transitive dependency trees for each extra.
- CI hint: rebuild quarterly with `pip-compile`. Between rebuilds the
  locks are immutable.

### Added - conformance test suite

- `nth_dao/conformance/` - vectors-based wire-protocol conformance.
  Vectors are written by `python -m nth_dao.conformance.regenerate` and
  shipped in `nth_dao/conformance/vectors.json`. The reference runner
  in `nth_dao/conformance/runner.py` verifies the Python implementation
  passes its own vectors.
- 22 vectors across 6 categories: `canonical_json`, `fingerprint`,
  `signature_verify`, `endorsement_canonical_payload`,
  `template_canonical_payload`, `replay_window`.
- `docs/CONFORMANCE.md` - contract for non-Python implementations.
  Wire-compatible = zero failures under the equivalent runner.
- 5 tests in `tests/test_conformance.py`.

### Added - A2A alignment report

- `docs/research/A2A_ALIGNMENT.md` - comparison vs Google's Agent2Agent
  protocol (Linux Foundation, Apache 2.0, 150+ orgs, v1.0 in 2026):
  identity, discovery, capability advertisement, task lifecycle,
  transport, trust, streaming, push, auth, marketplace, decentralization.
  Strategic conclusion: our protocol stays distinct (the deep choices
  are not reconcilable), but a v0.10.0+ `nth-dao-a2a-adapter` package
  will translate at the boundary. Adopt A2A vocabulary in user-facing
  docs; code names stay NTH DAO.

### Why these and not AgentLedger / DID:key

The v0.9.3 retrospective ("self-pivoting" 4-question check) identified
that *every* assumption about NTH DAO surviving 12+ months ran through
one of the six holes above:

  R-2 key recovery, R-3 observability, R-4 dep lockfile, R-5 upgrade
  path, M-2 ecosystem alignment, conformance for portability.

`AgentLedger` (history aggregation) and `DID:key` standards-compliance
have value but neither blocks survival. They're moved to v0.9.5.

### Tests

- Total: **169 passing + 1 skipped** (was 138 + 1). +31 tests covering
  the six holes above. No existing test regressed.

### No protocol changes

- `MissionTemplate`, `Mission`, `TeamConfig`, `Endorsement`, `Revocation`,
  `Invitation`, gossip envelope, LAN discovery - **all unchanged on disk
  and on the wire**. v0.9.3 artifacts are byte-identical to v0.9.4
  artifacts when produced by the same code path.

## [0.9.3] - 2026-05-31 - Mission templates: "decentralized App Store" layer

This release lifts MissionStore from a one-shot quest board into a reusable,
signed, rateable template registry. Aligned with cargo-crev / F-Droid / TUF /
Argo / GitHub Actions / Nix flake.lock - zero new runtime dependencies.

### Added - MissionTemplate (Layer 2)

- **`nth_dao/orchestration/template.py`** - `MissionTemplate` dataclass,
  `TemplateStore`, `mint_template()` helper, `TemplateType` enum (5 kinds:
  `agent_task`, `agent_chain`, `agent_dag`, `agent_review`, `human_in_loop`).
- **`IOField`** dataclass - `inputs` / `outputs` schema aligned with GitHub
  Actions `action.yml` field naming (description / type / required / default /
  values). Five primitive types: `string`, `int`, `float`, `bool`, `enum`.
- **`StepSkeleton`** - step blueprint with `inputs_from` sourcing
  (`"input:NAME"` simple form for v0.9.3).
- **Semver-validated `version`** - re-publishing same `(template_id, version)`
  errors unless `allow_overwrite=True`.
- **Publisher signature mandatory** - `TemplatePublishError` on bad sig
  before persistence.
- **Deprecation** - `templates.deprecate(publisher, id, version, reason)`;
  only the original publisher can deprecate; subsequent `instantiate()` of
  a deprecated template raises `ValueError`.
- **F-Droid/TUF-style derived index** - `_template_index.json` rebuilt on every
  publish with TUF-style `version` monotonic counter, `meta` map, and three
  inverted indexes (`by_category` / `by_publisher` / `by_capability`).

### Added - MissionReview

- **`nth_dao/orchestration/review.py`** - `MissionReview` dataclass,
  `ReviewStore`, `mint_review()` helper, `TemplateStats` aggregator.
- **Signed reviews** - append-only `reviews/<template_id>-v<version>.jsonl`,
  one signed line per review (cargo-crev Proof model).
- **Score range** 0.0–5.0 validated at mint.
- **Self-review rejected** - the mission owner cannot review their own work.
- **Dedup at read** - `only_latest_per_reviewer=True` keeps only the most
  recent rating per `(reviewer_pubkey, mission_id)`; the raw JSONL preserves
  every submission for audit.
- **EWMA aggregation** - `TemplateStats.weighted_average` uses
  α=0.3 EWMA so recent reviews count more without entirely overriding history.

### Added - Mission instance linkage

- `Mission.template_id`, `Mission.template_version` - link an instance to
  its template.
- `Mission.template_lock` - Nix-flake-lock-style snapshot of the publisher
  signature at instantiation time. A later re-publish (or in-place template
  tamper) cannot retroactively change the contract a running mission was
  built under.
- 5 reserved fields with empty defaults for Layer 3 (`owner_did`,
  `legal_jurisdiction`, `governing_arbiter`, `credentials_required`).
  Behavior is still empty; field names are now stable for future use.

### Added - MissionStore APIs

- `publish_template(template, allow_overwrite=False)`
- `list_templates(category=, publisher_pubkey=, required_capabilities=, include_deprecated=)`
- `browse_templates(category=, tags=, min_average_rating=, sort_by="rating"|"recent"|"popularity", limit=, include_deprecated=)`
- `instantiate(template_id, version=None, *, owner, inputs={}, scope, priority, title, goal)` - version omitted picks latest
- `review_mission(mission_id, reviewer, score, feedback)`
- `template_stats(template_id, version=None)`
- `archive_completed(older_than_days=30)` - atomic move of terminal missions to `archive/YYYY-MM/`
- `list_archive(year_month=None)` - read archived missions
- `my_history(agent_id, since=, include_archive=True, limit=)` - personal contribution view

### Added - language iron rule

`CONTRIBUTING.md` Hard Rules now includes a non-negotiable language-choice
rule: **TypeScript for UI / dashboards / browser extensions; Python for the
core protocol layer and everything else**. Different cadences want different
toolchains. UI changes weekly, protocol changes yearly.

### Added - docs

- **`docs/PROTOCOLS.md §9`** - full wire-format spec for MissionTemplate,
  MissionReview, derived index, mission template lock, archive layout, and
  the 5 Layer-3 reserved fields. Documents alignment with 7 industry
  standards.
- **`docs/CATEGORIES.md`** - recommended bootstrap taxonomy (Tier 1: 10
  well-known categories; Tier 2: emerging; Tier 3: discouraged).

### Tests

- 30 new tests in `tests/test_p7_template_review.py` covering mint /
  publish round-trip / tamper / semver / deprecation / instantiation /
  template_lock / latest-version selection / review signing / dedup /
  EWMA aggregation / browse sort orders / archive + history.
- Total test count now: **138 + 1 skipped** (was 102).
- `examples/template_demo.py` end-to-end walk-through.

### Aligned with (not depended on)

- cargo-crev - Proof model (sign-by-author, append-only, P2P)
- F-Droid metadata - one file per template + derived index
- TUF - `version` monotonic, `meta` field name, `delegations` placeholder
- Argo WorkflowTemplate - 5-value `template_type`
- GitHub Actions `action.yml` - input/output schema field naming
- Nix `flake.lock` - `template_lock` snapshot on instantiation
- W3C `did:key` - `publisher_did` field (simplified placeholder)

## [0.9.2] - 2026-05-31 - Revocation, invitations, LAN privacy, protocol spec

### Added - P6 follow-on roadmap items

- **Endorsement revocation** (`web_of_trust.py`):
  - New `Revocation` dataclass - owner-signed cancellation tied to a specific
    `(endorser, subject, issued_at)` triple.
  - `issue_revocation(endorser, endorsement, reason)` mints + signs.
  - `TrustGraph.revoke()` issues + imports in one call;
    `TrustGraph.import_revocation()` validates signature, requires a
    matching endorsement on disk (prevents pre-emptive DoS revocations),
    and dedupes.
  - `_load_all()` now filters out revoked endorsements; chains break
    immediately. Persisted at `team_trust/revocations.jsonl`.
- **Invitation tokens** (`nth_dao/invitation.py`):
  - New `Invitation` dataclass that bundles `team_id` + `owner_pubkey` +
    `join_token` + optional `ws_url` + optional LAN `psk`, signed by owner.
  - `Invitation.mint(team_config, owner_identity, ...)` - fails fast if the
    minting identity doesn't match `team_config.owner_pubkey`.
  - URL form: `nthdao+invite://<base64url payload>`, ≤ 2 KB so it fits
    inside one QR code.
  - `to_qr_terminal()` (qrcode lib only) and `to_qr_png()` (`pip install
    nth-dao[ux]`) render the URL as ASCII / PNG QR code.
  - `Invitation.from_url()` + `validate()` reject expired/tampered/wrong-scheme.
- **LAN discovery privacy** (`discovery/lan.py`):
  - New `psk=` argument on `LANDiscovery`. Both query and hello carry an
    `HMAC-SHA256(psk, nonce)` tag; responder only answers queries with
    matching tag, querier only accepts hellos with matching tag.
    `hmac.compare_digest` used throughout.
  - Empty `psk` = open mode (unchanged behavior, backward compatible).
- **`docs/PROTOCOLS.md`** - 350-line wire-protocol spec covering identity,
  gossip handshake + envelope, endorsements / revocations, signed team
  config, invitations, LAN discovery, marketplace orders, missions. Enables
  Rust / Go / TypeScript implementations to interop with the Python reference.
- **`CONTRIBUTING.md`** "Hard Rules" section documents the eight enforcement
  rules learned from the v0.9.1 review (file I/O via util, signed wire
  protocols, CAS for concurrency, no `except: pass`, etc.).

### Added - extras

- `[lan]` extra: `zeroconf>=0.131` (placeholder for v0.9.3 mDNS backend).
- `[ux]` extra: `qrcode[pil]>=7.4` for invitation QR rendering.

### Tests

- 19 new tests in `tests/test_p6_revoke_psk_invite.py`:
  - revocation round-trip, wrong-issuer rejection, immediate de-trust,
    cross-instance persistence, pre-emptive revocation drop,
    tampered-signature drop;
  - LAN PSK: blocks unauth queries, allows matching, rejects wrong PSK,
    backward-compat open mode;
  - Invitation: mint round-trip, validation, tamper rejection, expiry,
    non-owner mint rejection, wrong-scheme / garbage URL rejection, QR
    terminal rendering, helpful ImportError without extra.
- Total test count now: **102 + 1 skip** (was 83).

## [0.9.1] - 2026-05-31 - P0/P1 security & correctness review fixes

### Security
- **Gossip signature verification fixed**: messages are now verified against the *author's* trusted pubkey (not the relay peer's). Unsigned or mismatched messages are **dropped**, not silently accepted as before. A 10-minute replay window is enforced. `require_signature=True` is the new default.
- **WebSocket challenge-response handshake**: peers must prove possession of their declared pubkey (sign a server-issued nonce) before being added to the peer table. `GossipNode.trust_agent()` + `trusted_pubkeys=` constructor arg manage the trust anchor map; pubkey rotation triggers a `logger.warning`.
- **Atomic mission claim**: `MissionStore.try_claim()` uses cross-process file locks (POSIX `fcntl` / Windows `msvcrt`) plus compare-and-swap, raising `ClaimConflict` when another agent already owns the step. Includes a 6-process race test (`tests/test_concurrent_claim.py`) proving exactly-once semantics.
- **Mission FAILED terminal state**: missions with a failed step and no remaining actionable steps now transition to `FAILED` (previously hung in `ACTIVE` forever).
- **Constant-time join-token comparison**: `MembershipManager` uses `hmac.compare_digest`, preventing timing side-channels.
- **Private key file ACL on Windows**: `AgentIdentity.save()` tightens ACL via `icacls /grant ... /inheritance:r` with a post-write read self-check. Failures emit `logger.warning` instead of `except: pass` leaving keys world-readable.
- **Identity tamper detection**: `AgentIdentity.load()` derives the pubkey from the private key and refuses to load when the stored pubkey disagrees.

### Fixed
- Marketplace `reject()` now notifies the original claimant (replaced broken `hasattr('claimant_history')` always-False check that DMed `"unknown"`).
- Marketplace credits go through `_transfer_credits()` + append-only `*_credits.ledger.jsonl`, with insufficient-balance checks preventing local double-spend.
- Reputation `rate()` validates score range, rejects self-rating, supports `upsert=True` (replace latest), and rate-limits non-upsert calls per `(rater, subject, context)`.
- Reputation `get_all_scores()` / `top_agents()` reuse a single `_load_all()` pass (was O(N²)).
- Channel `fetch()` merges across files by timestamp before slicing `limit` (previously returned host-grouped, mis-ordered results, and `since_msg_id` could miss messages across files).
- Mission `update_step` no longer double-pushes `previous_assignees` when changing status+assignee in one call.
- `Mission.updated_at` is actually bumped on save (was a self-assignment no-op).
- `Mission.from_dict` no longer mutates the caller's dict via `data.pop`.
- `MissionRunner.handoff()` rejects empty targets, self-handoffs, and (when a registry is provided) dead targets.
- `PeerFinder.rank()` adds `min_match` parameter; the old `min_score=0.5` floor returned agents with 0 matching capabilities.
- `AgentRegistry.register()` registers `atexit` only once per instance instead of stacking callbacks across re-attaches.
- `attach()` does the membership check *before* creating the backend, preventing subprocess leaks on join failure; `detach()` calls backend `close/stop/shutdown` if available.
- Gossip `_recv_loop` no longer updates `last_seen` on a throwaway `PeerInfo` object (was a silent no-op).
- Channel `stats()` no longer reuses `_` as both iteration variable and filter predicate.

### Changed
- New `nth_dao/util/io.py` centralises `safe_id`, `atomic_write_json`, `atomic_write_text`, `safe_load_json`, and `InterProcessLock`. Six modules that previously copy-pasted `_safe_id` and atomic-write logic now share this util.
- `__version__` reads from `importlib.metadata` so it stays in sync with `pyproject.toml`.
- `groups.Channel` re-exported as `GroupChannel` alias to disambiguate from `channel.TeamChannel`.

### Added (tests)
- 20 new regression tests in `tests/test_p0_fixes.py` covering atomic claim CAS, mission FAILED state machine, identity tamper rejection, reputation rate-limits / upsert / anti-Sybil credits, marketplace double-spend prevention, channel fetch global sort, peer finder min_match, and handoff alive-check.
- Cross-process race test `tests/test_concurrent_claim.py` (spawn 6 workers -> exactly 1 winner, 5 ClaimConflict).
- Total test count: 45 (up from 23).

### P5 - "People nearby" discovery (chat app-inspired find-and-meet)

- **Fuzzy `PeerFinder.search(query)`** - substring / prefix / exact-match scoring across `agent_id`, `label` (extracted from `metadata["identity"]["label"]`), `capabilities`, and `groups`. Returns `MatchResult` list ranked by score, with `+0.5` idle bonus and configurable `limit` / `min_score` / `exclude_agent_ids` / `fields`. 10 new regression tests covering each scoring rule, label extraction, idle tie-breaking, self-exclusion, and limit.
- **`nth_dao/discovery/lan.py`** - zero-config UDP-based agent discovery on the local subnet. No mDNS / Bonjour, pure stdlib `socket`.
  - `LANDiscovery(agent_id, label, capabilities, ws_url, pubkey_hex, port=9877)` - call `.start()` to spawn a background responder thread that answers query packets that match its capabilities.
  - `LANDiscovery.discover(timeout=3.0, wanted_capabilities=None, target_addrs=None)` - broadcast a query (`255.255.255.255` by default; tests use `127.0.0.1`) and collect `LANPeer` responses for `timeout` seconds. De-duped by agent_id; results carry `ws_url` so the caller can hand them to `GossipNode.connect()` and `pubkey_hex` so they can be added to `TrustGraph.add_root()`.
  - Context-manager friendly (`with LANDiscovery(...) as lan: ...`).
  - Nonce-based response matching so stale replies are dropped.
  - Windows hardening: catches `ConnectionResetError` from ICMP "port unreachable" bleed-through that would otherwise blow up `recvfrom`.
- **`__init__.py` facade exports** `LANDiscovery` + `LANPeer`.
- 7 new LAN tests covering: peer found, capability filter, self-exclusion (loopback), empty result when nobody's listening, stale-nonce rejection, facade exports, context manager lifecycle.
- Total test count now: **83** (up from 66).

### P4 - Web-of-Trust: endorsement-based multi-hop trust

- **New module `nth_dao/web_of_trust.py`** with `Endorsement` dataclass, `TrustGraph` resolver, and `issue_endorsement()` helper.
- An `Endorsement` is a signed `{endorser_pubkey, subject_pubkey, subject_agent_id, depth_allowed, context, issued_at, expires_at, sig}` payload. `endorser.sign_json(endorsement.signable_dict())` produces the signature.
- `TrustGraph` stores root anchors in `team_trust/roots.json` and endorsements append-only in `team_trust/endorsements.jsonl`. `is_trusted(agent_id, pubkey, max_depth=2)` runs a bounded BFS, verifying the signature chain and respecting each endorser's `depth_allowed` cap.
- `GossipNode(..., trust_graph=..., wot_max_depth=2)` now falls back to the trust graph when an author's pubkey isn't directly pinned. Log lines tag whether trust came from `pinned` or `wot`.
- **Hop budget enforced correctly**: an endorsement with `depth_allowed=1` makes the subject a *leaf* - their own endorsements won't propagate further. Verified by `test_depth_allowed_caps_propagation`.
- 16 new tests in `tests/test_web_of_trust.py` covering: round-trip + sig verify, tampered endorsement, root direct trust, agent_id spoof rejection, 1-hop / 2-hop chains, expired endorsements, wrong-signer endorsements, `resolve_path` returns full chain, depth_allowed cap, invalid depth at issue, `trusted_pubkey_for` lookup, cross-instance persistence, facade re-exports, and gossip integration.
- Total test count now: **66** (up from 50).

### P3 - anti-tamper hardening

- **Signed team config (anti git-sync poisoning)**: `TeamConfig` gains `owner_pubkey` + `owner_sig` + `sig_updated_at` fields. When `MembershipManager` is constructed with an `owner_identity` that holds Ed25519 keys, every `save_config()` signs the canonical config. `load_config()` rejects (returns empty `TeamConfig()`) any signed file whose signature doesn't verify against its pinned `owner_pubkey` - meaning a malicious node can't `git push` a tampered `team.json` that adds themselves as admin.
- `MembershipManager.enable_signed_owner(identity, actor_id)` - admin-gated upgrade path to turn signing on for an existing unsigned team.
- `init_team(..., owner_identity=...)` - bootstrap a fresh team with owner signing in one shot.
- `attach()` auto-detects whether the agent is the legitimate owner (its pubkey matches the file's `owner_pubkey`) and only then activates owner-signing for that session - non-owner attaches read-only verify.
- **Reputation credits scoped by pubkey fingerprint**: when an `AgentIdentity` with crypto is passed, the anti-Sybil credit file uses `identity.fingerprint()[:16]` rather than `safe_id(agent_id)`. An attacker spawning 1000 `agent_id`s now still shares 5 starting credits per unique keypair (instead of 5 × 1000); legitimate single-keypair-multi-agent_id setups now correctly share one credit pool.

### P2 polish
- **Anti-Sybil rating credits** in `ReputationManager`: each new (non-upsert) `rate()` costs 1 credit; initial balance 5, daily refill +3 (cap 30). `rep.credits()` exposes current balance. Combined with the (rater, subject, context) rate-limit, this makes mass-rating costly without needing a global ledger.
- **Backend resource release**: `attach.detach()` now uses an explicit `_close_backend()` helper that probes `close` -> `stop` -> `shutdown` (in that priority order) and logs at debug when none exist.
- **Docstring de-mojibake**: replaced encoding-corrupted Chinese comments / docstrings in `nth_dao/__init__.py`, `nth_dao/attach.py`, `nth_dao/discovery/agent_registry.py`, `nth_dao/orchestration/mission.py`, `nth_dao/orchestration/mission_store.py`, and `nth_dao/orchestration/mission_runner.py` with English equivalents that match the actual behavior. (The old files contained `""`-only docstrings after the encoding loss.)
- `AgentRecord.short()` no longer uses empty strings as alive/dead markers (replaced with `*`/`-`).
- `agent_registry` heartbeat-tick failure is now logged at debug instead of silently swallowed.

## [0.9.0] - 2026-05-28

### Added
- Added a minimal `nth_dao.web` local console with membership-gated group chat,
  announcements, tasks, and audit-backed state APIs.
- Published the NTH DAO manifesto as the public mission statement.
- Completed the hard rename to **NTH DAO** / `nth_dao` and removed the old public package name.
- Added `AgentIdentity` / `AgentID` identity primitives with optional Ed25519 signing via the `crypto` extra.
- Added `attach(..., identity=...)` support and discovery metadata export without bypassing membership approval.
- Added identity tests for persistence, attach metadata, and membership-gated identity use.
- Added `VISION.md` and `CONTRIBUTING.md` to document the decentralized Agent-to-Agent identity/group direction and review bar.
- Added basic `TeamRole` role/permission hints for owner, admin, and member flows.
- Added a local-first `GroupManager` with `Channel`, `Message`, `Announcement`, `Task`, `AuditEvent`, and `TrustHint` primitives.
- Added `MembershipRequest` as a semantic alias for `JoinRequest`.

## [0.8.1] - 2026-05-27

### Fixed
- Made membership approval an actual `attach()` gate before heartbeat/discovery registration.
- Added admin checks for approval, rejection, invites, member removal, admin changes, and policy changes.
- Accepted string join policies such as `"approval"` in addition to `JoinPolicy` enum values.
- Ensured open/token joins persist approved agents into `team.json` member state.
- Cleaned the membership module encoding/comments and removed trailing whitespace issues.

### Added
- Added focused membership tests for approval blocking, admin approval, open joins, token joins, and string policy compatibility.
- Added test path setup for `examples/` bot imports and cleanup for generated test `team.json`.

## [0.8.0] - 2026-05-25 (Initial extraction)

First standalone release, extracted from `AlexNthLab/hermes-team-agent`
where it was developed in-tree as `team_layer/` + `nth_dao/`.

### Added - All 8 PRs from the original development branch

#### PR 1: `team_layer/runtime.py` - Core adapter (250 lines)
- `TeamAgent` lightweight wrapper around any backend
- `TeamMemoryManager` orchestrating multiple providers
- `<memory-context>` fence injection to prevent identity confusion
- `MemoryProviderABC` with 5 lifecycle hooks (init/prefetch/sync_turn/pre_compress/end)

#### PR 2: `team_layer/memory_providers/` - 4 default providers (520 lines)
- `SoulProvider` - lazy-load TEAM-SOUL.md (<200 tokens)
- `UserModelProvider` - auto-sediment preferences across sessions
- `VectorProvider` - skill registry indexer
- `LedgerProvider` - append-only experience ledger

#### PR 3: `team_layer/compression/` - 5-tier pipeline (330 lines)
- Budget Reduction -> Snip History -> Microcompact -> Collapse -> Auto-summary
- Cheap operators first (zero-cost trims before expensive LLM summarization)
- `preserved-tail` mechanism keeps recent 3 turns at full fidelity

#### PR 4: `team_layer/evolution/` - EvoLoop self-evolution (1189 lines)
- `EvoTrigger` - ROI-lagged gate (`count >= 3 AND wasted > budget * 1.5`)
- `Reflector` - generates fix Patch from failure samples (LLM-optional, template fallback)
- `Verifier` - subprocess sandbox + Pydantic contract validation (replaces Z3)
- `EvolutionGate` - auto-merge low-risk, queue high-risk for human review
- Append-only `evolution_audit.jsonl` with full audit trail

#### PR 5: `team_layer/git_sync/` - Multi-terminal sync (1191 lines)
- `LogCollector` - zero-collision naming `{host}_{user}_{ts}.jsonl`
- `SkillLoader` - atomic `git checkout -- skills/` for hot-reload
- `CentralAggregator` - merges all terminal logs, runs EvoLoop, emits PR-ready report
- GitHub Action `team-evolve-daily.yml` for nightly aggregation

#### PR 6: `team_layer/blackboard/` - Multi-agent shared workspace (1132 lines)
- 3 scopes: `shared` / `group:<name>` / `private:<agent>`
- Append-only version chains (full history)
- Kanban renderer (TODO/DOING/DONE/BLOCKED)
- CLI: `python -m team_layer.blackboard list|view|post|update|history`
- `BlackboardProvider` injects per-agent task view into system prompt

#### PR 7: `team_layer/backends/` - AgentBackend ABC (2016 lines)
- Unified interface for any agent framework
- 6 built-in backends:
  - `mock` (always available, deterministic)
  - `hermes` (subprocess)
  - `claude_code` (stream-json CLI)
  - `openclaw` (ACP HTTP)
  - `codex` (OpenAI Codex CLI)
  - `openhands` (REST API)
- `BackendRegistry` with availability probing
- `TeamAgent.run_with_backend()` for backend-driven main loop

#### PR 8: `nth_dao/` - Pluggable facade (2096 lines)
- Re-exports the core DAO/group APIs through the `nth_dao` public package
- `discovery/` - heartbeat-based peer discovery + capability search
- `orchestration/` - Mission/Step relay across sessions and agents
- `attach()` - one-line integration: `team = nth.attach(agent_id, backend, ...)`
- `TeamSession` facade combining agent + memory + blackboard + discovery + missions
- `INTEGRATION_GUIDE.md` with Hermes / Claude Code / OpenAI examples
- `pyproject.toml` ready for PyPI release

### Verified
- 5 working end-to-end demos in `examples/`
- All demos run zero-deps on stdlib-only Python 3.10+
- 9170+ lines of production code
- Self-improving loop verified: failure -> ledger -> EvoLoop -> skill -> next session prefetch

### Notes
- Extracted to this standalone repo to enable `pip install nth-dao`
  for use across agent frameworks and local-first DAO nodes.
- New integrations should use `import nth_dao as nth`; the former
  `nth_team_layer` public package is intentionally removed.

[0.9.6]: https://github.com/AlexNthLab/nth-dao/releases/tag/v0.9.6
[0.9.5]: https://github.com/AlexNthLab/nth-dao/releases/tag/v0.9.5
[0.9.4]: https://github.com/AlexNthLab/nth-dao/releases/tag/v0.9.4
[0.9.3]: https://github.com/AlexNthLab/nth-dao/releases/tag/v0.9.3
[0.9.2]: https://github.com/AlexNthLab/nth-dao/releases/tag/v0.9.2
[0.9.1]: https://github.com/AlexNthLab/nth-dao/releases/tag/v0.9.1
[0.9.0]: https://github.com/AlexNthLab/nth-dao/releases/tag/v0.9.0
[0.8.1]: https://github.com/AlexNthLab/nth-dao/releases/tag/v0.8.1
[0.8.0]: https://github.com/AlexNthLab/nth-dao/releases/tag/v0.8.0

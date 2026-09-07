# NTH DAO Plugin Architecture

Status: design contract for the first plugin-kernel implementation.

## Purpose

NTH DAO is not a model, an agent, a wallet, a marketplace operator, or a
universal chat application. It is a local-first protocol host for identity,
discovery, communication, coordination, authorization, fulfillment, evidence,
receipts, and disputes between humans and agents.

Plugins make transports and providers replaceable. They do not make the trust
model replaceable.

## Three Architectural Layers

### Constitution layer

The constitution contains invariants that every runtime and plugin must obey:

1. Identity keys remain under explicit owner or delegated custody.
2. Signed artifacts use the versioned canonicalization and verification rules.
3. Authority comes from mandates and capability grants, never from a plugin
   merely being installed or discovering an object.
4. Event, receipt, and dispute evidence remains append-only and verifiable.
5. Stateful transitions use the protocol's CAS, idempotency, and outbox rules.
6. Irreversible actions require deterministic validation and explicit commit
   authority.
7. Unknown fields, permissions, protocol versions, and signature algorithms
   fail closed at security boundaries.
8. A plugin may add policy but may not lower a host security ceiling.

The constitution is implementation-independent. A future Rust, TypeScript, or
WASI host must preserve the same invariants.

### Versioned protocol layer

This layer defines language-neutral envelopes and conformance vectors for:

- identity and capability grants;
- messages and collaboration events;
- tasks, missions, checkpoints, and handoffs;
- intents, agreements, mandates, and orders;
- deliveries, receipts, disputes, and governance decisions;
- plugin manifests and capability contracts.

Protocol objects are not Python class identities. Wire compatibility is based
on a versioned schema, canonical bytes, and conformance tests.

### Replaceable runtime layer

Runtime components may be replaced when their declared capability contracts
are compatible. Examples include agent providers, discovery transports,
message stores, market indexes, settlement adapters, and observability sinks.

## Plugin Kinds

The first host recognizes these namespaces:

| Kind | Responsibility |
| --- | --- |
| `agent.provider` | Invoke or supervise an external agent runtime. |
| `discovery.provider` | Produce untrusted or verified peer/listing hints. |
| `transport.provider` | Move protocol envelopes without changing authority. |
| `message.store` | Retain, expire, or delete collaboration messages. |
| `market.index` | Index signed listings; never become listing authority. |
| `commerce.connector` | Connect to an external commerce system. |
| `payment.rail` | Prepare or commit settlement through a payment provider. |
| `settlement.adapter` | Validate and translate settlement protocol objects. |
| `trade.execution` | Execute a signed Trade Rule operation within grants. |
| `intent.resolver` | Convert human or agent input into an unsigned draft. |
| `intent.solver` | Propose plans or offers for a reviewed intent. |
| `intent.policy` | Deterministically evaluate a proposal against policy. |
| `artifact.store` | Store content-addressed evidence or deliverables. |
| `identity.resolver` | Resolve identifiers without granting authority. |
| `observability.exporter` | Export bounded, redacted operational signals. |

These terms remain distinct:

- A **host plugin** extends the local NTH DAO runtime.
- An **A2A extension** negotiates an optional wire-protocol feature.
- A **Trade Rule Skill** defines transaction terms and execution rules.
- An **Agent Skill** describes an agent's advertised ability.

Installing one never implies installing or authorizing another.

## Manifest

Every plugin declares a bounded manifest before activation:

```json
{
  "manifest_version": 1,
  "plugin_id": "org.nth-dao.discovery.federation",
  "version": "2.0.0",
  "host_api": "1.0",
  "kind": "discovery.provider",
  "runtime": "builtin",
  "provides": [
    {
      "capability_id": "org.nth-dao.discovery.federation",
      "version": "2.0.0",
      "input_schema_digest": "sha256:<64 lowercase hex characters>",
      "output_schema_digest": "sha256:<64 lowercase hex characters>",
      "effects": [
        "filesystem-read",
        "filesystem-write",
        "network-read",
        "network-write"
      ],
      "consistency": "C1",
      "privacy": "workspace",
      "security": "verified-input",
      "cardinality": "many",
      "deterministic": false,
      "retention": "ephemeral",
      "failure_semantics": "retry-safe"
    }
  ],
  "requires": [],
  "permissions": [
    "filesystem.read.workspace",
    "filesystem.write.workspace",
    "network.client"
  ],
  "artifact_digest": "sha256:<64 lowercase hex characters>",
  "publisher_did": "",
  "proof": ""
}
```

The host accepts statically registered `builtin` plugins and one explicit
`subprocess` path for locally reviewed worker artifacts. An in-process Python
import is arbitrary code execution, not a sandbox. The subprocess path is not
package discovery: remote manifests, Python entry points, signed third-party
packages, and downloaded commands remain unsupported. WASI or a platform OS
sandbox is still required before community code can be treated as confined.
Existing built-ins retain their Host API `1.0` minimum. The subprocess runtime
requires Host API `1.1`; an older `1.0` host therefore rejects it explicitly
instead of interpreting a new runtime under an unchanged compatibility claim.

`publisher_did` and `proof` are reserved wire fields in Host API v1. Both
reviewed registration paths reject non-empty values because this release does
not yet define or verify an external package signature. A shaped proof is not
treated as authentication.

## Capability Contract

`provides` is more than a name. Each capability declares:

- capability identifier and semantic version;
- input and output schema digests;
- observable effects;
- consistency class;
- privacy and security class;
- provider cardinality;
- determinism, retention, and failure semantics.

The initial consistency classes are:

| Class | Meaning |
| --- | --- |
| `C0` | Ephemeral presence or best-effort chat. |
| `C1` | Mergeable collaboration state; duplicate-tolerant. |
| `C2` | Workflow state requiring CAS, idempotency, or an outbox. |
| `C3` | Economic state requiring authoritative receipts. |
| `C4` | Identity or governance state requiring versioned/quorum authority. |

A provider with a matching method name but a different effect, consistency,
privacy, or failure contract is not compatible.

Host API v1 accepts a strict, bounded JSON Schema subset. Object schemas must
reject undeclared properties, arbitrary regular expressions are unsupported,
and each invocation input and output is normalized through canonical JSON
with a 1 MiB document limit. These constraints keep schema metadata
enforceable at the call boundary rather than advisory.

C2, C3, and C4 capabilities must also register both input and output semantic
validators. Capabilities whose responses carry request identity or limits must
also register an exchange validator, and resource-addressed effects must use an
authority validator before provider invocation. The Host runs those validators
around every invocation and rejects
an operation-tagged response that does not echo its request operation. This
prevents accidental omission of CAS or state-machine validation merely because
the base schema digest matches. A no-op or dishonest validator cannot be
detected mechanically: validators remain reviewed in-process code, not proof
of provider correctness, and their source artifact remains part of the plugin
trust decision.

The Host retains its own canonical request snapshot and passes a separate deep
copy to the provider. Exchange validation always uses the original snapshot,
not the provider's possibly modified input. Every semantic, authority, exchange,
and response-context callback receives isolated JSON copies. Synchronous
mutation fails validation; retained references cannot change the Host's request
or returned response after a callback finishes. These are data-integrity
guarantees, not an in-process code sandbox.

A capability may also register a `response_context_validator`, which the Host
runs after output and exchange checks against its own invocation context. It
can bind a response to the selected plugin, invocation ID, and principal scope;
a provider-supplied context is never substituted for the Host's context.
The callback receives a detached response copy, and mutation fails validation
instead of changing an already checked result.
Top-level `invocation_context_digest` is reserved for this boundary. A schema
containing it must require the field and register input, output, exchange, and
response-context validators, even for C0 capabilities. Missing callbacks fail
registration; dishonest no-op callbacks remain part of reviewed Host code.

## Lifecycle And Authorization

The lifecycle is deliberately split:

1. `install`: make a manifest and factory known to the host;
2. `authorize`: grant an explicit subset of its declared permissions;
3. `enable`: resolve dependencies and start the provider;
4. `disable`: remove capabilities first, then stop runtime effects;
5. `uninstall`: remove a disabled plugin and its grants.

`install != enable != authorize`. A plugin cannot self-grant permissions.
Unknown permissions are rejected. Missing required permissions prevent enable.
Profiles may select a set of plugins, but cannot expand host policy.

Risk tiers guide isolation:

| Tier | Examples | Minimum execution policy |
| --- | --- | --- |
| `T0` | Schemas and static metadata | Pure data validation. |
| `T1` | Deterministic transforms | In-process is acceptable. |
| `T2` | Workspace reads | Built-in initially; scoped read grants. |
| `T3` | Network, filesystem writes, subprocesses | Built-in initially; subprocess isolation before third-party support. |
| `T4` | Credentials, identity delegation, payment commit | Separate process or WASI-style isolation plus explicit mandate. |

Permission metadata does not sandbox in-process Python. Until an isolation
backend exists, only reviewed built-ins may run in process.

Lifecycle changes are written to a bounded, append-only local hash chain. It
detects truncation, malformed transitions, and ordinary record mutation, but
it is not signed and is not authoritative against an attacker who can rewrite
the entire workspace. The host restores grants and the desired state from this
projection but never auto-enables a plugin after restart.

Web-initiated authorization, enable, disable, and manual refresh events also
bind the authenticated principal class and the authorized membership actor.
Legacy audit records without this attribution remain readable. A local console
running with authentication disabled is recorded honestly as
`anonymous-local`, never upgraded to an authenticated console identity.

A reviewed built-in whose manifest digest changes must use the explicit
upgrade registration path. The audit binds the previous and replacement
digests, then clears every grant and the desired-enabled flag. Code upgrades
therefore require fresh operator authorization instead of inheriting authority
from a different artifact.

In-process startup is also cooperative: Host API v1 keeps plugin code outside
the global registry lock, but Python cannot safely terminate a factory or
`start()` call that never returns. This is another reason third-party runtimes
require a subprocess or WASI isolation phase.

### Reviewed subprocess RPC v1

`register_reviewed_subprocess()` is a narrow migration boundary, not a public
plugin installer. Trusted host code supplies an absolute launcher, one local
entry artifact, a controlled working directory, explicit arguments, and an
explicit environment. The Host verifies the entry artifact SHA-256 at
registration. It rejects launcher symlinks, stores the resolved launcher path,
binds the launcher bytes into the local launch profile, and rechecks them at
registration and immediately before process creation. At start it reads the
source once, verifies those bytes while
copying them into a private, workspace-local per-generation snapshot, and executes only that
snapshot. A source-path replacement after the verified read therefore cannot
change the launched entry bytes. It never invokes a shell and
does not inherit `PATH`, `PYTHONPATH`, user secrets, or arbitrary environment
state. Transitive interpreter dependencies and operating-system trust remain
outside that digest, and
the entry-artifact digest does not prove the contents of dynamically imported
modules. A future signed package format must bind the complete artifact graph.
The local launch profile separately hashes the launcher path and bytes, artifact path,
working directory, arguments, explicit environment key names, timeouts, and byte
limits. Environment values never enter a public hash commitment. A profile with
explicit environment values instead receives a random process-local binding, so
it requires fresh authorization after fresh launch-spec reconstruction. Only the resulting
digest enters the audit. A profile change clears all grants
and desired state before registration completes, so reviewed authority cannot
silently migrate to different launch behavior after restart.
Each live generation holds a cross-process lease outside its snapshot directory.
Normal cleanup failures fail the lifecycle operation instead of being swallowed;
the next subprocess registration removes only inactive, strictly named Host
generations and audits both janitor success and failure.

The worker uses newline-delimited canonical JSON with the fixed protocol name
`nth-dao-plugin-rpc` and version `1`. Startup requires an exact nonce-bound echo
of plugin ID, manifest digest, and sorted capability IDs. Calls carry a
Host-generated invocation ID and a Host-derived authority projection. RPC
objects use RFC 8785-compatible UTF-16 key ordering, reject floats, and restrict
integers to `-(2^53-1)..(2^53-1)` for JavaScript-safe interoperability. Exactly
one request may be in flight per worker. Results must bind the invocation ID,
use exact fields, and remain within a 2 MiB frame. A bounded business error does
not revoke the worker only when its retry hint agrees with the capability's
declared failure semantics. An input that the RPC subset cannot represent, or
that exceeds a worker's configured frame, is rejected before pipe I/O and does
not revoke the worker. A timeout, crash, idle process exit, malformed or non-canonical JSON,
unsolicited output, oversized output, or binding mismatch terminates the
supervised process, attempts descendant cleanup, atomically removes its
complete provider generation, records `plugin.runtime.failed`, and fails
closed. `disable()` can interrupt a blocked call rather than waiting for its
normal RPC timeout. A platform job/container boundary is still needed to make
descendant containment authoritative.

Stderr content is never copied into Host errors or audit records. The Host
retains only a bounded byte count and a process-local keyed fingerprint for
diagnosis, so low-entropy text cannot be tested against a public raw digest;
excessive stderr is a protocol failure. The checked-in
`plugins/vectors/subprocess-rpc-v1.json` file fixes canonical examples for
handshake, invocation, success, error, shutdown, and non-BMP object-key order.
The test suite executes those vectors through Node.js as an independent
consumer rather than relying only on Python round trips.

This boundary contains observed process crashes, invocation hangs, idle exits,
and protocol pollution. It does **not**
prevent a malicious child running as the same operating-system user from
opening files, using the network, spawning another process, or inspecting
other user-readable resources. It also does not impose CPU or memory quotas;
an idle but resource-hungry child requires a Windows Job Object, cgroup,
container, or WASI boundary. Therefore it does not yet authorize arbitrary
third-party plugins or any irreversible capability.

## Irreversible Effects

Runtime registration can be reversible; real-world side effects cannot. A
payment, message delivery, shipment, or remote deletion follows:

```text
observe -> propose -> prepare -> authorize -> commit -> receipt
                                                    -> compensate (optional)
```

Every commit binds an idempotency key, the applicable mandate and terms,
deadline/timeout policy, executor identity, and a durable receipt. A plugin
cannot describe a committed external effect as "rolled back" merely because it
was disabled.

Host API v1 rejects every T4 capability and every capability classified as
`irreversible`; a weaker self-declared security label cannot make
`credential-use`, `payment-prepare`, or `payment-commit` executable. Merely
requiring mandate and idempotency strings would not prevent a crash between an
external commit and local persistence. T4 execution remains disabled until an
OS-confined executor, complete artifact verification, durable idempotency
ledger, prepare/commit recovery, and receipt reconciliation are implemented
and tested together.

## Failure And Recovery

- One malformed manifest must not prevent safe-mode startup.
- A failed plugin is quarantined with bounded diagnostic text.
- Capability registration is atomic: partial provider maps are never visible.
- Disable removes routing before invoking plugin cleanup.
- Startup and cleanup failures are auditable but cannot forge success.
- Plugins must declare whether retry is safe, best effort, at-most-once, or
  fail-closed.

## Reference Migration

The first reference plugin wraps existing federation discovery without
changing feed digests, peer identity verification, DNS/IP pinning, cache
limits, or wire endpoints. It proves host lifecycle and capability resolution;
it does not rewrite the federation protocol.

The web runtime statically registers this reviewed adapter and exposes its
status through `/api/plugins`. Registration deliberately does not authorize,
enable, or invoke network access. An administrator can explicitly enable it
through `/api/plugins/{plugin_id}/enable`; the web-owned periodic worker then
invokes federation discovery only through the revocable capability binding.
The adapter and Market views share one bounded cache, so plugin results are
visible without a second projection or wire format.

The built-in manifest's artifact digest covers the adapter, federation
traversal/cache, peer registry, verified network binding, and the focused
signed-identity trust kernel. The production registration API constructs that
kernel itself and does not accept replacement peer-verification or HTTP-read
callbacks. Seed selection, shared cache ownership, and optional reverse hello
remain typed host services; they cannot turn an unverified hint into a trusted
peer. The FastAPI application is not part of the artifact, so unrelated Web/UI
edits do not invalidate plugin authorization. Low-level provider constructors
retain dependency injection only for isolated tests and are not the reviewed
registration boundary.

Workspaces that have never selected a plugin runtime retain the legacy poller
as a compatibility fallback. Once the operator enables or disables the
federation plugin, that preference is persisted locally. Explicit disable is
fail-closed across process restarts and never silently falls back to the
legacy network path. Plugin code still owns no hidden thread: FastAPI lifespan
owns, stops, and joins the consumer worker.

The second reference provider is an optional curated-registry accelerator. It
is installed but unauthorized and disabled by default, reads its opt-in HTTPS
index URL from `NTH_CURATED_REGISTRY_URL`, and requires the publisher trust root
in `NTH_CURATED_REGISTRY_PUBLISHER_DID`. Its v2 index is signed and carries a
monotonic version plus a bounded issued/expiry window. The host persists each
publisher's accepted version and signed-envelope digest so an old index cannot
be replayed after restart, while an identical interrupted refresh can retry.
Bounded index rows are merely candidate peer URLs with optional DID
hints. A host-owned admission service, not provider code, independently DNS
checks and IP-pins every row, verifies the peer's signed identity card,
constrains any DID hint, and applies the same TTL/network quotas as gossip
peers. DNS uses bounded daemon workers and HTTPS uses an absolute socket
deadline, so a stalled resolver cannot block lifecycle control indefinitely.
Registry and gossip hints always require public HTTPS. An operator-configured
seed or source-bound LAN discovery result may explicitly use private HTTP(S),
but it receives a `configured` endpoint scope and still uses a pinned IP,
signed identity card, bounded response, and absolute deadline.

Manual refresh uses a non-blocking per-plugin lease and a per-operator rate
limit. The global lifecycle lock is released before network I/O; PluginHost's
generation and active-call accounting make concurrent disable revoke the
provider and wait for the bounded invocation. Before any refresh side effect,
the host appends a `plugin.refresh.started` intent. Completion or failure binds
the same invocation ID, and unmatched intents are exposed in plugin status for
crash/audit recovery. Successful imports become ordinary learned peers and are
reverified again by federation polling before use. A registry outage or
malicious row cannot erase local state or forge a verified peer result.
Because accepted publisher versions and learned peers are persisted, the
capability declares durable retention and retry-safe failure semantics. A
workspace-wide lease covers version acceptance through every learned-peer
write, so an older process cannot resume stale side effects after a newer
index. Retrying the same version is allowed only when its signed-envelope
digest is identical; lower versions and same-version content conflicts fail
closed. Legacy v1 version-only state requires one publisher version increment
before this retry guarantee becomes available.

### Agent provider reference

The first `agent.provider` reference freezes
`org.nth-dao.agent.session` v2 as a bounded, principal-scoped session
capability. Its wire operations are `probe`, `open`, `turn`, `status`,
`close`, and `cancel`. Prompts are confidential and sessions are ephemeral.
The v1 contract remains accepted only with its exact historical schema and
digest. V2 adds explicit temperature-support advertisement; it does not mutate
v1 in place.
Every turn carries a caller-stable `turn_id`; a provider must cache the result
for the session lease, return it with `replayed=true` on an identical retry,
and reject reuse of that ID with different input. Numeric model controls use integer
`temperature_milli` and `timeout_ms` fields because canonical JSON rejects
floating-point values. `open.max_tokens` is the maximum output-token count for
each turn. A provider must enforce it, and an adapter must reject a response
whose reported `output_tokens` exceeds it; accepting the configuration is not
proof that the provider honored the budget.

The complete protocol document also fixes a 1 MiB canonical-JSON UTF-8 limit
for both directions and operation-specific output state rules. A schema-valid
response is still rejected unless identifiers, `ready`/state, final status,
turn counters, replay marker, error, and tool-call fields agree with the
operation. Implementations must apply both schema and semantic validation.

Invocation input cannot select an executable, import path, environment,
credential, working directory, tool policy, or arbitrary backend options.
Those controls remain host-owned. The explicit
`nth_dao.plugins.agent_backend_adapter.PluginAgentBackend` proxy implements
the existing `AgentBackend` interface over a compatible provider binding, so
`attach()` and orchestration do not gain a parallel Agent facade. The proxy
accepts only complete, exact contract profiles: legacy v1, the ephemeral v2
profile, or the supervised durable-network v2 profile. Schema, effects,
consistency, privacy, security, retention, and failure semantics must all
match; a matching capability name or version is insufficient.

The distribution always registers a self-contained offline Mock provider. It
has no external effects, runtime loader, or permissions and remains disabled
by default. It caps global and per-principal sessions, uses a
15-minute renewable idle lease, limits turns per session, rejects concurrent
turns with a fail-fast busy result, protects an in-flight turn from idle
reaping, and lets idempotent `cancel` bypass the turn lock. Its wire capability reports
`supports_streaming=false` because this contract has no streaming operation.
This is a conformance and lifecycle sample.

Each successfully spawned or restored localhost A2A Agent is now also
registered as a distinct, fixed-DID supervised provider. Registration leaves
it unauthorized and disabled. Its manifest declares network read/write and
`network.client`; the plugin never receives the child port, CapToken, command,
environment, credential, or workspace path. A Host-owned invoker reuses the
existing supervisor, work-scope lease, CapToken refresh, localhost A2A, signed
Receipt verification, and Receipt persistence path. A successful turn is
accepted only after the Receipt is bound to the fixed target DID, plugin turn,
method, prompt hash, response hash, requested model, and the canonical digest
of all Host-owned execution controls. The target cannot be selected in an
invocation document. Goal is bound into that digest even though the current
child does not consume it as prompt text. The provider reports temperature and
multi-turn support truthfully and rejects unsupported overrides. Until a
tokenizer-specific accounting contract exists, the output budget uses UTF-8
bytes as a conservative upper bound rather than claiming exact model tokens.
The v2 turn response carries the paired `receipt_id` and
`receipt_content_hash`; `PluginAgentBackend` preserves them in
`TurnResponse.metadata`. They identify the verified audit artifact but do not
prove that the Agent's answer is factually correct.

The Web invoker persists a workspace-local, inter-process-locked state machine.
State v3 binds a stable execution-target revision derived from DID, Agent ID,
backend kind, declared capabilities, work-scope access, and work revision. A
localhost port change is transport churn and does not change that revision; a
changed execution scope causes old state recovery to fail closed under the
original logical turn key.
Target lookup completes before `prepared` is written. `dispatched` is written
immediately before the coroutine crosses the A2A boundary, and `completed` is
written only after the signed Receipt and response bindings pass one shared
validator. A prepared turn may be resumed; a dispatched turn may only be
reconciled from a matching verified Receipt. If the Receipt proves execution
but the response body was lost, the state records that fact and refuses to
execute again. Retrying an outcome-unknown turn runs that reconciliation path;
it does not cross the A2A dispatch boundary again. A received response which
fails envelope, budget, or Receipt validation enters a terminal `rejected`
state with no response body persisted and cannot be re-executed. Completed
response bodies have a seven-day local replay window;
expired results are atomically reduced to hash/Receipt tombstones. The bounded
hot cache may evict an older completed response body, but writes a sharded
tombstone first and never evicts idempotency evidence. Capacity is consumed by
unresolved hot states; saturation by those states fails closed. This
provides local at-most-once dispatch across crashes; it does not claim remote
exactly-once semantics. The supervised provider therefore declares durable,
confidential retention rather than claiming ephemeral storage.
Child and invoker free-text errors are not returned or persisted because they
may contain local paths, command lines, credentials, or provider output.

Stopping an ephemeral supervised Agent disables and uninstalls its generated
plugin registration. A persistent roster Agent is disabled while its plugin
and identity material are retained. If the roster is unreadable or malformed,
cleanup fails safe and retains the plugin rather than guessing that it is
ephemeral.

The production manifest's reviewed source set includes the Web invoker and
the CapToken, Supervisor, child A2A, work-scope, bounded-response, and Receipt
trust path. A change anywhere on that path changes the manifest digest; Host
API v1 then clears prior grants and returns the plugin to disabled. This digest
is still an unsigned local change detector, not publisher attestation or a
complete transitive Python build proof.

The current SDK/CLI child backends cannot reliably interrupt a provider call.
The bridge therefore returns an unconfirmed cancellation failure for an
in-flight turn instead of killing an entire child and calling that a
session-scoped acknowledgement. Idle sessions can still close or cancel
locally. A future child cancellation protocol must bind target DID, session,
turn, authorization, and a signed stop acknowledgement before this behavior
can change. Direct in-process wrapping of Claude Code, Codex, or Hermes remains
rejected.
Importing the wire contract or PluginHost does not import the legacy
`team_layer` package. The package facade resolves legacy runtime exports lazily,
and only callers that explicitly request `PluginAgentBackend`, call `attach`,
or request a legacy backend load those modules. The Mock artifact digest binds
an explicit reviewed source set and detects ordinary local/package drift. It is
unsigned, excludes the Python/package trust base and transitive import graph,
and is not publisher attestation. A changed built-in manifest resets grants and
returns to disabled state; external plugin distribution remains out of scope
until signed, immutable build artifacts are supported.

`PluginAgentBackend` adds host-owned policy above the language-neutral wire:
an optional model must be allowlisted, session token and timeout controls may
only narrow configured ceilings, and a returned tool call is exposed only when
both the adapter policy and that session requested the exact tool name. The
provider never receives executable paths, credentials, environment variables,
or an authority to execute a tool merely because it proposed one.

### Message storage boundary

`org.nth-dao.message.store` v1 defines a closed, language-neutral storage
capability for opaque canonical-JSON message documents. The Host remains
responsible for membership, signatures, mandates, and choosing the invocation
principal. `InvocationAuthority` is a host-selected in-process scope, not a
remote signature or identity proof; Host API v1 trusts the embedding
application to derive it from an already verified boundary. Providers isolate
records by that local principal and by an explicit namespace; callers cannot
supply or override a principal in the wire document. Namespaces are opaque
identifiers, never filesystem paths, so durable providers must hash or encode
them before storage. Message IDs are immutable idempotency keys bound to the
complete stored record, while list cursors use monotonically increasing
sequence values. Destructive operations also bind the expected sequence and
content digest, preventing delayed requests from deleting a replacement.

The reviewed `org.nth-dao.message.memory` provider is installed disabled and
does not replace or dual-write the existing Channel JSONL store. It is bounded
by record, principal, byte, TTL, and document limits and supports an atomic
in-process `consume` operation. Its deletion guarantee is explicitly
`logical-only`: it does not claim secure erasure from process snapshots, swap,
logs, disks, backups, or remote replicas. A future durable provider must
declare its real filesystem or network effects and a distinct exact contract
profile even when it implements the same wire schema.

### Transport boundary

`org.nth-dao.transport.delivery` v1 moves opaque canonical-JSON protocol
envelopes without becoming an identity, membership, mandate, or message
authority. The Host verifies authorization before send and must reverify the
received envelope's signature and protocol semantics after delivery. A route
ID is an opaque provider locator, not a URL, DID resolution result, or proof of
the remote sender.

The v1 operations are `probe`, `send`, `receive`, and `ack`. `delivery_id`
binds immutable send input, while `receive_id` binds one expiring exclusive
lease. Acknowledgement atomically closes the complete batch using its lease ID
and ordered content digest. An unacknowledged batch may be delivered again
after lease expiry, so application handlers remain idempotent. The ephemeral
profile provides at-least-once delivery only within the provider lifetime; it
is neither durable delivery nor exactly-once processing.

The reviewed `org.nth-dao.transport.loopback` provider is a bounded,
in-memory conformance sample. It derives each local inbox route from the
Host-selected principal, accepts no caller-supplied source identity, has no
network or filesystem effects, and is installed disabled. It does not replace
gossip, A2A, Channel persistence, or federation discovery. Future HTTP,
Bluetooth, relay, or other transports must declare their actual effects and
exact capability profile; sharing method names does not make a network
provider compatible with the local ephemeral profile. Provider-scoped
transport delivery IDs disambiguate equal caller IDs from different senders.
Unexpired acknowledgement evidence is never evicted; capacity exhaustion
fails closed. Empty receive IDs retain their binding only through the requested
lease. Terminal non-empty claim evidence has a separate five-minute retry
window, while sender delivery tombstones remain until the envelope expires.
Byte, claim, and idempotency quotas are isolated per invoking principal as well
as globally.

### Market index boundary

`org.nth-dao.market.index` v1 is a closed, language-neutral search projection
over Host-verified Task and Trade Offer discovery claims. It does not merge
those source protocols and cannot create, amend, claim, negotiate, agree,
deliver, settle, or certify a listing. Every projected entry binds the exact
source protocol, source object ID, publisher DID, source content digest, and
locator. A caller must resolve and independently reverify that exact signed
source object before any action. An index result remains a publisher claim,
not proof of truth, ownership, availability, price, inventory, or authority.

The Host selects the local invocation principal; wire input cannot override
it. `upsert` and `remove` use content-digest CAS, with identical retries
remaining idempotent. Search filters are closed and bounded. Ranking is
provider-specific, but every result includes an integer score and uses
publication time plus entry ID as a stable tie-break. Pagination cursors are
opaque, principal- and normalized-query-bound snapshot tokens. The reference
provider rejects a cursor after that principal's index revision changes,
after five minutes, or when filters/page size change rather than silently
mixing pages from different views. Entry expiry is evaluated against the first
page's fixed snapshot time within that bounded cursor lifetime.

The reviewed `org.nth-dao.market.memory-index` provider is bounded by entry,
principal, byte, tombstone, query, page, and document limits. Its cursor is
authenticated with a process-local HMAC key. It is installed disabled and
does not replace, dual-write, or become authoritative over the current Market
feed, federation cache, Task store, Offer store, REST API, or UI. It is a
conformance sample for future local, federated, community relay, or centralized
accelerator indexes. Network and durable implementations must declare their
actual effects and exact contract profile. Sharing the v1 capability ID and
input/output schema digests establishes wire compatibility only; it does not
make two provider profiles exact contract substitutes. A provider must also
preserve the non-authoritative protocol semantics, and the Host must explicitly
allow every declared external effect before selection. Checked-in JSON vectors freeze the
entry schema, operation schemas, protocol digest, positive inputs, and one
cross-language canonical content address.

### Intent resolver boundary

`org.nth-dao.intent.resolve` v1 converts a bounded human, agent, or system
request into an unsigned, review-required `IntentDraft`. Input and output bind
the exact request ID, source text, source kind, locale, automation ceiling, and
digest-addressed attachment metadata. Attachment digests, media types, and
sizes are fixed as `unverified` caller claims; validation of referenced bytes
belongs to a separate Host-owned artifact boundary. A resolver response declares
`authority=none`, `commit_authority=false`, and `executable=false`. It cannot
create a Task, Mission, Agreement, Offer, Mandate, capability grant, payment,
or execution request. Any such promotion is a distinct future signed protocol
operation outside this capability.

The Host-owned `IntentEnvelope` v1 wire primitive now exists separately from
the resolver. It signs only explicit draft acceptance, with no commit authority
or executable flag. It requires a current, trusted acceptance context, exact
draft/source binding, and closed solver/time/scope bounds. No signing provider,
automatic key loading, REST/UI promotion, durable replay store, or execution
path is introduced by the wire primitive. The separate
[local acceptance journal](INTENT_ACCEPTANCE.md) now adds explicit Host SDK
nonce/revision CAS and atomic local audit persistence; it does not enable
business promotion. A separate
[Host policy snapshot](INTENT_POLICY.md) now deterministically resolves direct
  member DID, role, revocation, reviewed-draft and solver/automation bounds. Its
  append-only local store now retains canonical snapshots and serializes current
  head changes with governed journal acceptance. Authenticated governance-source
  ingestion remains outside this primitive. An explicit
[Spine bridge](INTENT_ACCEPTANCE_SPINE.md) adds node-signed, hash-only observation
anchors and recoverable replay; no automatic publication or signing provider
capability is enabled.
See [Intent Envelope v1](INTENT_ENVELOPE.md).

The reviewed `org.nth-dao.intent.literal-resolver` is an offline conformance
sample. It performs no model inference, stores no request, requests no Host
permissions, and always asks for explicit outcomes and constraints. It is
installed disabled and is not wired to application workflows or UI. Its
checked-in schemas and canonical JSON, digest, authority, and source-binding
vectors are exercised by Python and an independent Node test consumer. The
Node consumer validates the entire schema tree, including unused optional
fields and array items, and checks operation-specific and cross-field semantics.
It rejects unsupported schema keywords and is not a general JSON Schema
implementation. Negative vectors require explicit validation failures in both
languages, not identical diagnostic wording or accidental runtime exceptions.
A detached resolver response is unsigned: its `resolver_id` is a claimed label,
not cryptographic provenance, and `source_kind` does not authenticate a source.
The response's invocation-context digest is verified by a Host-side callback;
it rejects blind replay across calls or principals but is not a detached proof
of origin. Draft content stays stable across identical requests, while the
response wrapper changes for each invocation. Resolver v1 defines no business
error codes: malformed input and revoked bindings fail at the Host boundary.
A future model-backed resolver must declare its real network, subprocess,
privacy, and retention profile and remain an untrusted hint producer; sharing
the wire shape does not grant it authority.

The reviewed `org.nth-dao.intent.review-solver` is the corresponding disabled,
offline `intent.solver` conformance sample. Its input requires a valid signed
IntentEnvelope plus exact Host authority bindings to the acceptance audit,
governing policy, proposal idempotency key, and invocation-materialized evidence. It
returns an unsigned `claim_status=unverified` proposal with no authority or
execution flags. Host invocation binding identifies the live plugin call but is
not a detached signature. Model-backed solvers, durable proposal storage,
deterministic proposal policy, selection, and promotion remain unimplemented.
Application integration must use the Host-owned governed invocation builder;
copying audit, policy, or time fields into a raw request is not authorization.
See [Intent Solver Proposal v1](INTENT_SOLVER.md).

Migration order:

1. plugin manifest, capability contract, registry, and lifecycle tests;
2. federation discovery as a reviewed built-in provider;
3. optional curated registry discovery as an accelerator whose results are
   reverified by the trust kernel (reference provider implemented);
4. agent backends (offline reference and fixed-DID supervised A2A bridge
   implemented; signed remote cancellation remains), message retention
   (ephemeral reference implemented), then transport providers (local
   loopback contract and disabled reference implemented; network adapters
   remain);
5. non-authoritative market index contract and bounded in-memory reference
   (implemented; existing Market reads are not migrated or dual-written);
6. reviewed subprocess RPC foundation (implemented for static local workers;
   OS sandbox and signed package loading remain);
7. non-authoritative Intent resolver v1 and disabled literal reference
   (implemented; signed envelope v1 wire/signature/context checks implemented;
   local acceptance journal with nonce/revision CAS, opt-in signed Spine anchors,
   a content-addressed local membership/role/revocation policy gate, and a
   disabled review-only SolverProposal boundary implemented; model-backed
   solvers, governance ingestion, proposal policy/selection/promotion, and UI
   remain);
8. settlement and payment providers only after OS confinement, complete
   package verification, durable idempotency and mandate-bound commit tests
   exist.

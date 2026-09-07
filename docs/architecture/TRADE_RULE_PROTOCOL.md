# Trade Rule Protocol Boundary

Status: accepted for the first implementation slice
Scope: NTH DAO trade protocol v2

## Decision

NTH DAO will provide a stable, local-first protocol kernel for discovering,
negotiating, accepting, executing, and auditing trade rules. It will not encode
one universal commercial rulebook in the Core.

Third parties may publish signed, content-addressed Trade Rule Packages. Each
node decides locally whether to cache, install, trust, reject, or execute a
package. Final Orders bind exact package and dependency digests.

Manifest signature verification proves integrity and publisher-key control. It
does not prove that a rule is safe, trusted, currently acceptable, or suitable
for a trade. Expiry, recognition, revocation, and local policy remain separate
decisions.

## Stable Core

The Core owns:

- NTH Trade Canonical JSON;
- DID signatures and signature domain separation;
- principal-to-agent authority;
- strict Rule Manifest parsing and package digests;
- capability and exact-digest negotiation;
- proposal and acceptance;
- immutable Order snapshots;
- authorized append-only events;
- evidence and signed Receipts;
- replay, size, time, and resource limits;
- fail-closed handling of unsupported required rules.

## Tasks and Market Offers

Tasks remain the demand and collaboration entry point. A Task may be local,
federated, unpaid, or carry a bounty. Claiming a Task creates or links exactly
one Mission; the Mission owns execution state and the Blackboard exposes the
human-visible process.

Market Offers are separate. They describe products, services, or any mutually
accepted exchange without treating money as a privileged resource:

```text
free service          provides=[service]       requests=[]
paid product          provides=[product]       requests=[fiat or token]
barter                provides=[product]       requests=[product]
product for service   provides=[product]       requests=[service]
asset swap            provides=[bitcoin:btc]   requests=[solana:spl:<mint>]
```

Trade Offer v2 therefore uses signed `provides` and `requests` resource legs
rather than a mandatory price field. Resource types, identifiers, units, and
Rule IDs are open namespaced strings. Descriptors and selected Rule Packages
are bound by exact SHA-256 digest. UI categories such as Product and Service
are projections for people, not closed protocol enums.

Every resource leg requires a content-addressed descriptor. Resource IDs use a
bounded URI-like namespace and reject executable or local-path schemes. An
Offer is an immutable revision: revision 1 has no predecessor; each later
revision binds the exact previous Offer digest. `withdrawn` is terminal.
Registries key lifecycle chains by `(publisher_did, offer_id)` and must retain
forks as conflicts rather than silently applying last-write-wins.

The local Offer Store is an append-only JSONL fact source. It stores each
signature-valid content digest once and derives lifecycle views without
rewriting signed records. Out-of-order revisions remain `incomplete` until
their predecessor arrives. Equivocating roots or successors remain `forked`;
known-invalid edges remain `invalid`. No conflicted chain is promoted to a
canonical head. A malformed, oversized, empty, or duplicate stored line blocks
the projection instead of silently restoring an older active revision.

Each local envelope binds its sequence, predecessor envelope hash, Offer
digest, receipt time, and import provenance into a SHA-256 hash chain. A
durable checkpoint detects tail truncation; after a crash, a fully fsynced and
valid tail may advance a stale checkpoint. Record count, total bytes, and line
size are bounded. Local API imports also emit a signed
`trade.offer.imported` Spine event binding the exact sequence, envelope hash,
Offer digest, publisher, Offer ID, and source. Read APIs fail closed if an
existing signed import anchor no longer matches the Offer log.

These controls detect corruption, one-sided rollback, and many accidental
recovery errors. They are not external consensus or immutable storage. An
operator with write access who rolls back both the Offer log and the signed
Spine can still erase local history. Federation must retain and compare signed
heads across nodes before stronger rollback-resistance can be claimed.

An Offer is a signed claim, not proof that an item exists, a valuation is fair,
or settlement is safe. Publishing or verifying an Offer never transfers an
asset. Negotiation must later produce an immutable Order that binds the exact
Offer and Rule Package digests. Funds-capable execution requires a separately
installed, locally approved Adapter and a signed Mandate.

Signature integrity and current activity are separate decisions. Integrity
verification proves the publisher and immutable bytes. Activity evaluation
also checks publication time, expiry, and withdrawal state. Neither decision
grants local trust or confirms that referenced assets exist.

## Extension Boundary

Rule Packages may describe pricing, quantity, fulfillment, acceptance, payment,
dispute, rights, privacy, compliance, or future families. Family and applicable
subject identifiers are open, namespaced strings rather than a closed Core enum.

The manifest parser may preserve declarations for future `adapter`,
`sandboxed_wasm`, and `external_service` modes. Parsing such a declaration does
not make it installed, trusted, ready, or executable. The first implementation
executes nothing and supports only declarative interpretation. A package cannot
execute Python, JavaScript, shell commands, or remote code. Future executable
behavior must use a separately installed, locally approved Adapter implementing
a versioned Hook Contract.

JSON Schema is an interoperability aid, not the complete validator. The
protocol parser additionally enforces bounded canonical JSON, semantic timestamp
ordering, exact DID verification methods, canonical ordering for set-like
arrays, and contradictory-reference rejection.

Untrusted but structurally valid input uses `InspectedTradeRuleManifest` and an
`unverified-sha256:` inspection digest. Only `TradeRuleManifest` represents a
publisher-signature-verified snapshot and may produce the package identity
`sha256:` digest. Both Python and TypeScript verification freeze the exact
canonical bytes before any cryptographic operation.

Verified Rule Packages are cached locally by the exact signed manifest digest.
Every declared resource must be present, and its byte length and SHA-256 digest
must match the manifest. Resources are written before the manifest; the
manifest is the package commit marker. Loading re-verifies the publisher
signature and every resource. The cache never imports or executes Python,
JavaScript, shell code, WASM, or remote services.

Rule Package Bundle v1 is the bounded federation envelope for that immutable
content. It carries an Offer-publisher-signed, domain-separated assertion over
one exact Offer digest and Package digest, plus the signed Manifest and
digest-sorted, canonical-base64url resources.
The public endpoint serves only Packages reachable through a currently live,
locally published Offer; it is not a Package-store enumeration API. Import is
an explicit operator action bound to an already-audited local Order. Parsing
rechecks the Manifest signature, every resource hash and size, the Package
digest, and the Offer/Order binding before installing the non-executing cache.
A successful import explicitly grants neither publisher trust nor Adapter or
funds execution authority. The Offer-to-Package binding signer must be the
exact publisher DID carried by the signed Offer; a valid signature from any
other DID is unauthorized. Public Package responses have a dedicated
cross-process request budget, are conservatively byte-budgeted before signing
or base64 encoding, and hold a concurrency slot across the full verification
and encoding path;
stable tuple ETags permit a verified live Offer to return 304 without
rebuilding the Bundle. Imports single-flight per Package digest across local
processes before writing the content-addressed cache and share a bounded set
of OS-backed cross-process import slots across different digests. Before cache
installation, the importer writes an idempotent
`trade.rule-package.import.proposed` Spine event. The final
`trade.rule-package.imported` event uses the same semantic ID derived only from
the Order and Package digests; changing a peer URL cannot create a second
semantic import. Both events bind the Order, Offer, Package, Rule ID, Package
publisher, and the peer origin. URL paths, queries, fragments, and credentials
are not retained in audit data. If cache installation succeeds but the final
Spine append fails, execution fails closed for that Order and for any other
Order attempting to reuse the as-yet-unanchored cache. A later retry reuses the
verified cache and repairs the missing signed audit before reporting success.

The Package Store persists a canonical, bounded provenance sidecar after the
content-addressed Manifest commit. Acquisition sources are explicit:
`local` means an operator-controlled local installation and `federated` means
the package passed through the peer importer. A Package with no sidecar is
`unclassified`; this is the safe migration state for legacy or interrupted
installs and is inspectable but not executable. Federated-only provenance must
have at least one complete, semantically bound proposed/final Spine import
pair. Explicit local provenance does not require a federation import event,
but it grants neither publisher trust, Rule Recognition, nor execution
authority; current local policy must still approve the exact signed Package.
An interrupted provenance write therefore fails closed and can be repaired by
an idempotent reinstall without rewriting immutable Package content.

The authenticated local Trade Skill catalog exposes bounded summaries and one
exact signed Manifest through `/api/v2/trade/rule-packages`. Under one package
store lock, a page scan checks the bounded store shape and replays full Package
verification only for the selected page. It never returns resource bodies, and
responses are marked `Cache-Control: no-store`. Catalog responses call
the Package a verified cache entry, set recognition to `not-evaluated`, and set
execution authority to false. They also expose the derived import-audit state
(`not-applicable`, `anchored`, `incomplete`, or `mixed`) from signature-verified
Spine events and the persisted acquisition provenance (`explicit` sources or
`unclassified`). The Market UI preserves and displays those distinctions and
must not infer "local" merely from the absence of an import event.
`/api/v2/rules` is reserved for local automation/approval Rules and must not
project Trade Rule Packages into that unrelated data contract.

Rule resolution is policy-driven and exact-digest only. The resolver walks
bounded dependency graphs, rejects missing packages, conflicting packages,
multiple digests for one Rule ID, inactive manifests, unavailable
capabilities, and disallowed execution modes or permissions. Publisher trust
does not grant executable authority: every non-declarative package also needs
approval of its exact digest. Order-facing resolution selects only the
canonical Offer lifecycle head; forked and orphan revisions cannot proceed.
Resolver-returned package objects are not trusted assertions: resolution
rebuilds each package from its signed manifest and exact resource bytes before
applying recognition policy. The aggregate resource-byte budget is part of the
canonical local policy snapshot.

Canonical resolution returns an immutable binding to the selected Offer
digest, revision, canonical lifecycle chain, evaluation time, exact Rule
Package set, and canonical local-policy digest. A later Order can therefore
consume one snapshot without re-reading mutable lifecycle or policy state.
Proposal and Acceptance construction still query the local Offer resolver
again before signing. A caller cannot turn a hand-constructed
`CanonicalRuleResolution` into evidence that a stale or forked Offer was the
current canonical head. The supported signing API does not accept a caller-
supplied raw body, and it rechecks the canonical head after producing the
signature.

Package-store paths reject symlinks and Windows junctions inside the configured
store. Crash residue is reported by a reconciliation operation. Reconciliation
is dry-run by default; orphan resources and temporary files are removed only
after an explicit `prune=True` request. Missing resources are reported and do
not cause the signed manifest to be deleted.

## Trust and Recognition

Package trust is a local projection. A package cannot declare itself trusted.
Community, DAO, industry, or standards bodies may issue signed recognition,
deprecation, or revocation statements. Those statements inform local policy and
never become an unconditional Core whitelist.

Trade Rule Recognition v1 binds one issuer, Rule ID, and exact Rule Package
digest into a signed, sequence-linked statement chain. A successor must bind
the exact predecessor digest. Forks and missing predecessors fail closed.
Future successors do not replace the latest statement effective at the local
evaluation time. Every statement has a mandatory expiry, and local policy
bounds its maximum lifetime.

Each node chooses trusted recognition issuers, a threshold, and explicit Rule
ID scopes for every issuer. The projection reports
`observed_quorum_met`, never global acceptance: a decentralized node cannot
prove that an unavailable newer revocation does not exist. It also reports the
time through which the currently observed quorum can survive without renewal.
Invalid federation input is quarantined independently and cannot suppress a
valid observed view; strict replay remains available for detecting corruption
inside a locally verified store.

Recognition is advisory and deliberately separate from execution authority. A
recognized package is not automatically inserted into
`approved_executable_digests`, does not grant Adapter permissions, and cannot
authorize funds. Operators may use the projection as one input when building
their local `RuleResolutionPolicy`, but the protocol kernel does not silently
mutate that policy. This preserves the intended model: communities publish
Trade Skills and opinions about them, while each user or DAO decides which
rules it will accept and which executable artifacts it will separately
approve.

Verified Recognition statements may be imported into a bounded,
content-addressed local CAS. Invalid input bytes are not retained; the
quarantine stores only a digest, reason code, and observation time. Store reads
reverify signatures, package bindings, filenames, and path safety.

Local audit projection persists the exact signed statement in the CAS before
appending one idempotent `trade.rule.recognition.recorded` event to the signed
Spine. The Spine payload binds the statement digest, Recognition ID, Rule ID,
package digest, issuer, sequence, decision, and validity interval. If a process
stops after the CAS write, package-scoped reconciliation can recover the
missing anchor without resubmitting the statement. Cross-log verification
fails closed on missing, duplicate, conflicting, or orphaned local anchors.
The CAS therefore acts as the recovery source, not as a second audit ledger.

The Web v2 boundary exposes this flow through:

- `POST /api/v2/trade/rule-packages/{digest}/recognitions` to verify, store,
  and anchor an already issuer-signed statement;
- `GET /api/v2/trade/rule-packages/{digest}/recognitions` to return statements
  only after CAS/Spine cross-log verification succeeds; and
- `POST /api/v2/trade/rule-packages/{digest}/recognitions/reconcile` to repair
  store-first crash residue from the current pending set.

Writes require the normal console authorization boundary and a signed local
Spine. They never fall back to unaudited CAS persistence. Request bodies are
bounded before parsing. Reconciliation is stateless across calls, stops at the
first anchor failure, and returns the blocked digest plus a stable error code.
An orphan or conflicting Spine anchor is rollback evidence and blocks both new
writes and reconciliation until the exact signed statement is restored or an
operator resolves the integrity incident.

The node's interpretation policy is itself a signed, durable v1 chain rather
than an ephemeral constructor argument. Its stable `policy_id` is derived from
the genesis node DID. After genesis, that DID is the permanent policy namespace
rather than an alias for whichever signing key is currently loaded. An
authorized replacement key can reopen the existing namespace after restart
only when the previous signed revision names its DID as a controller. The
genesis revision must be signed by the namespace DID; each
successor must be contiguous, bind the exact predecessor digest, and be signed
by a controller authorized in the previous revision. A revision can rotate the
next controller set without requiring a central registry. This makes offline
replay deterministic: controller authority is carried by the signed history,
not by a mutable callback or server-side ACL.

Policy revisions are persisted as canonical, content-addressed statements plus
a durable rollback-detecting head. The store writes first and the signed Spine
then records one exact, idempotent
`trade.rule.recognition.policy.updated` event. Bounded reconciliation repairs
only exact store-first revisions. Missing, duplicate, conflicting, forked, or
orphaned facts fail closed. Read projections pin and recheck both policy and
Recognition snapshots around audit verification so a concurrent append cannot
silently enter an already-verified response. A time-pinned projection selects
the highest verified policy revision whose `issued_at` is not later than the
requested time. Future revisions are scheduled state, not retroactive policy;
a time before genesis has no active policy and fails explicitly.

The local Web v2 policy boundary provides:

- `POST /api/v2/trade/recognition-policy` for an already signed revision;
- `GET /api/v2/trade/recognition-policy` for bounded newest-first history;
- `POST /api/v2/trade/recognition-policy/reconcile` for exact crash recovery;
  and
- `GET /api/v2/trade/rule-packages/{digest}/recognition-evaluation` for a
  time-pinned advisory snapshot.

Policy history and evaluation are sensitive local-console reads. Policy writes
and reconciliation currently require the per-process local console Bearer
token even if the request carries a cryptographically valid CapToken: signature
validity alone grants no governance authority. A dedicated node-issued policy
capability is not defined in v1. Mutations share a cross-process persistent
rate limit, are body-bounded before parsing, and never degrade to unaudited
storage. Operational exceptions are logged locally while HTTP responses expose
stable error codes without filesystem paths. An observed quorum still returns
`execution_authorized: false`; a separate signed `RuleResolutionPolicy` and
Adapter approval remain mandatory for execution.

Observed issuer-chain federation is available through bounded signed proof
documents. The legacy v1 bundle carries at most 256 statements. Proof Page v2
splits graphs of up to 16,384 statements into independently signed pages while
committing every page to the same observation digest, complete statement-set
digest, graph-head digest, page count, and validity window. Both formats bind a
live public Offer to the exact Package using the Offer
publisher's signature, then disclose the locally audited Recognition graphs
selected by the node's explicit issuer allowlist. Each graph carries complete
predecessor closure and the exact set of observed terminal heads, including
forks. The Offer publisher signs the complete wrapper, its observation and
expiry times, and an explicit head-set digest. This prevents a relay from
stripping a revocation or branch and recomputing the wrapper. The observer
signature attests only to what that node disclosed at that time; authority over
each opinion remains in its issuer-signed Recognition statement.

The public endpoint is:

- `GET /api/v2/trade/federation/offers/{offer_digest}/rule-packages/{digest}/recognition-proof`
  for a short-cache legacy v1 proof;
- `GET /api/v2/trade/federation/offers/{offer_digest}/rule-packages/{digest}/recognition-proof-pages/{page_index}`
  for one page from a byte-stable, short-cache v2 observation;
- `POST /api/v2/trade/orders/{order_digest}/rule-packages/{digest}/recognitions/import`
  for an operator-directed, Order-bound pull from an explicit peer; and
- `GET .../recognitions/imports` plus `POST .../recognitions/imports/repair`
  for authenticated status and exact content-addressed evidence repair.

The import boundary reuses DNS-pinned federation transport and requires the
Package to be locally available with acceptable provenance and import-audit
state. The signed proof is first retained in content-addressed local storage.
A signed `trade.rule-recognition-proof.import.proposed` Spine event binds the
source origin, Order, Offer, Package, proof digest, observer, observed head-set,
and exact statement digests. The v2 payload additionally binds page index/count,
observation digest, total statement count, and statement-set digest. Statements
are capacity-checked and written under bounded Store/Spine batches. A matching signed
`trade.rule-recognition-proof.imported` event makes the batch visible. Reads
fail closed while a proposal is incomplete, a v2 page set is incomplete or
inconsistent, or its completed statements are missing from local CAS. Retry
recovers staged pages locally before making another network request. Normal
projection does not reparse every historical source envelope; authenticated
status and explicit deep-audit paths reverify retained proof CAS, and exact
repair bytes must hash to the proof digest already committed by the Spine.
This covers common-root forks and multiple-genesis
conflicts without exposing a valid partial chain. Retries remain
content-addressed and idempotent.

This exchange still does **not** prove global freshness: a peer can withhold a
newer signed revocation. A successful import does not add trusted issuers,
change the local Recognition Policy, approve an Adapter, or grant execution or
funds authority. It may affect advisory evaluation only when the importing
node already trusts that issuer for the exact Rule scope. Deleting both the
local CAS and Spine can still erase local history until another node presents
a signed conflicting head.

Recognition v1 has no signed audience field, so local records are not publicly
redistributed by default. Serving the endpoint requires both
`NTH_FEDERATE_RULE_RECOGNITIONS=1` and an explicit comma-separated issuer list
in `NTH_FEDERATE_RULE_RECOGNITION_ISSUERS`; `*` is the explicit opt-in to relay
all issuers. Existing records therefore remain local after upgrade. Operators
must still avoid placing confidential assessments in this v1 statement kind;
future audience-restricted claims require a different signed wire contract.

## Bilateral Agreement and Order

Trade Agreement v1 adds a deliberately small bilateral consent sequence for
Trade Offer v2:

```text
signed Offer
    -> signed Proposal by the taker
    -> signed Acceptance by the Offer publisher
    -> deterministic immutable Order snapshot
```

The Proposal binds the exact Offer digest and revision, canonical lifecycle
digests, selected Rule Package digests, the taker's canonical local-policy
snapshot and digest, terms, and an expiry. It cannot outlive the signed Offer.
The Acceptance binds the exact Proposal digest, the same Offer and Rule Package
set, and the maker's independently evaluated canonical local-policy snapshot
and digest. It must be created no earlier than the Proposal and before the
Proposal expires. The supported creation APIs resolve and sign as one operation
and re-read the current unambiguous canonical Offer head after signing, closing
the raw-body and check/sign timing bypasses.

Local creation defaults to a seven-day maximum Proposal lifetime and a
five-minute signing-clock tolerance. Implementations may choose stricter
values. These checks protect the local signer; `proof.created` remains a signed
claim rather than a trusted global timestamp. A receiving node needs a durable
receipt or timestamp witness before claiming when a remote signature was
actually produced.

Proposal federation uses a separate `nth.dao.trade.proposal-delivery` v1
envelope. The taker signs the exact Proposal digest, embedded Proposal,
sender DID, recipient DID, a 128-bit-or-larger nonce, and a delivery window no
longer than ten minutes. A Delivery cannot predate or outlive its Proposal.
The envelope authorizes only retention by the named maker; it does not grant
acceptance, reservation, execution, or settlement authority. The public HTTP
receiver applies per-source and aggregate persistent budgets before parsing,
then replays the Proposal against its current local Offer lifecycle and Rule
Package state. Valid Proposals enter a bounded content-addressed inbox and one
idempotent `trade.agreement.proposal.received` Spine projection. The Proposal
digest is the semantic idempotency key, so replaying the same or a newly
wrapped Delivery cannot create a second retained claim. Retention commits only
when the maker writes a receiver-signed `tradeProposalIntakeReceipt` after the
Delivery and Proposal replay succeed. The receipt binds the Delivery digest,
Proposal digest, sender, receiver, and local receive time. A bare Proposal or
Delivery file is therefore not sufficient for startup recovery to make the
maker sign a Spine event. Existing committed results are returned before
replaying later Offer state, so retry acknowledgement remains stable after an
Offer revision or withdrawal.

Startup reconciliation repairs an interrupted intake-to-Spine projection
without peer resubmission. Operators can retry the same recovery through the
authenticated `POST /api/v2/trade/proposals/reconcile` endpoint. Reconciliation
failure responses identify each affected digest with a bounded error code and
operator message. The authenticated
`GET /api/v2/trade/proposal-reconciliation/status` reports active records,
pending anchors, and the oldest pending age without exposing Proposal content.
Public federation errors use stable codes and do not disclose local paths or
raw persistence exceptions. A persistent
usage ledger removes per-write history scans and is rebuilt at startup; global,
per-taker, and per-Offer quotas limit active inbox exhaustion. Signed intake
records remain immutable evidence and are not silently deleted at expiry.
Expired records leave active quotas only after the receiver appends a signed
`trade.agreement.proposal.archived` Spine tombstone. The complete Delivery and
intake receipt are copied into content-addressed archive storage before the
active receipt commit marker is removed. Startup recovery and
capacity-pressure intake retry this process, so archive failure leaves either
the original active record or a complete archived copy.

The Order adds no fictitious third agreement signature. It is a deterministic,
content-addressed snapshot of the already signed Offer, Proposal, and
Acceptance. Any conforming node with those three objects must derive identical
Order bytes and an Order ID derived from the Proposal digest. The local Order
CAS cache uses inter-process locking, atomic writes, bounded storage, strict
path validation, and idempotent compare-and-set. Multiple valid Acceptances for
one Proposal are retained and exposed as an explicit conflict; they are never
resolved by last-write-wins. Every Offer root Rule reference must appear in the
Proposal and Order binding. Conflict lookup is scoped by Order prefix and all
retained candidates count toward the configured record limit.

The CAS cache is not an audit ledger and cannot independently detect an
operator rolling back or replacing both data and local metadata. Accepted
Orders therefore use a bounded write-ahead audit outbox. The recoverable state
machine is `prepared -> cached -> anchored`: the full verified Order is
persisted before the CAS write, while the Spine event contains only exact
digests, party DIDs, and the agreement timestamp. Recovery can recreate a
missing cache entry, find an exact already-appended anchor, and finish the
state transition without duplicating the event. A claimed `anchored` state is
never trusted by itself; it is rechecked against the verified Spine chain.
Conflicting or malformed anchors fail closed.

Crash reconciliation is dry-run by default. It reports temporary residue,
corrupt records, and conflict candidates whose primary Order is missing.
`prune=True` removes temporary files only; it never deletes signed Orders,
conflict candidates, or corrupt evidence.

These signatures prove which keys made the Offer, Proposal, and Acceptance and
that the bytes have not changed. They do not prove that an asset exists, that a
description is honest, that either party controls inventory or funds, that a
Rule Package is socially trustworthy, or that delivery or settlement occurred.
An Order is an agreed execution input, not a Receipt and not a payment record.

Before execution, a node must call the Rule execution-readiness gate with its
current local policy. The gate reloads every content-addressed package,
recursively resolves all dependencies under both signed party-policy snapshots
and the executor's current policy, and requires each result to match the exact
Order bindings. The resulting readiness snapshot includes the union of
required capabilities, permissions, and execution modes across the complete
dependency closure. Package manifests are also reevaluated at execution time.
Offer activity is replayed at the signed acceptance time: expiry of a market
listing does not erase an already accepted Order, while expiry of an executable
Rule Package still blocks execution.

An executor may then issue a Trade Execution Receipt v1. The Receipt binds the
exact Order digest and ID, the complete execution-readiness snapshot and
digest, the executor's current policy digest, the ordered Rule Package
digests, a content-addressed Adapter identity, a content-addressed result, and
zero or more content-addressed evidence items. The execution ID is derived
only from the immutable Order digest, operation ID, and executor DID. One
bilaterally signed operation grant therefore has one terminal Receipt identity.
Multiple separately auditable attempts require separately granted operation
IDs; a signer cannot evade conflict detection by inventing a new opaque
idempotency commitment.

Version 1 accepts only the Order maker or taker as the Receipt signer and
requires the declared role to match the signed Order. Third-party Agent
execution is intentionally rejected until a signed, revocable delegation
capability can be verified. The creation API re-runs the execution-readiness
gate at `started_at`; an Adapter execution mode outside that result is
rejected. The Adapter descriptor is loaded through a local resolver by exact
content digest. Its ID, version, execution mode, supported Rule Hook, and
permission set must match both the signed Receipt/Rule and explicit local
Adapter policy. The descriptor is an allowlisted identity for executable
code; it is not itself an execution sandbox.

Permissions are scoped twice. The readiness snapshot retains the union across
the complete dependency closure so local policy can see the total requirement.
Each Hook contract separately declares the exact permissions granted to its
Adapter, and that set must be a subset of its own Manifest
`execution.permissions`. An unrelated dependency cannot enlarge the current
Hook's Adapter authority.

Both operation input and result descriptors must resolve to exact bytes under
their declared digest and size before signing or receiver acceptance. The Hook
input and output schemas must be immutable resources embedded in the same Rule
Package. Input is always validated; a successful result is also validated
against the output schema. The core exposes an injected schema-validator
contract and the optional `nth-dao[trade-validation]` extra supplies a JSON
Schema 2020-12 adapter.

Receipt timestamps use one canonical UTC representation: whole seconds omit
the fractional component, and nonzero fractions contain exactly six
microsecond digits. Nanosecond-looking strings are rejected rather than
silently truncated and reattached as false precision.

A Trade Execution Receipt is a signed claim, not an oracle. Its signature
proves who made the claim and that its bytes are unchanged. Content digests
make results and evidence addressable, but do not prove that those bytes are
truthful, complete, available, or sufficient. Receipt creation does not run an
Adapter, transfer an asset, mutate an Order, settle payment, or grant
reputation. A receiving node must call
`verify_execution_receipt_under_policy()` with its own Rule Package resolver
and local Rule and Adapter policies, content resolver, and schema validator
before relying on the claimed readiness; a valid party signature cannot bypass
that replay. Receipt issuance is exposed through
`TradeExecutionCoordinator`, which writes through the conflict-retaining CAS
before returning. Before touching that CAS, the coordinator prepares a bounded
write-ahead execution-audit record containing the exact signed Receipt and
Order bytes. It then stores the Receipt and projects one exact
`trade.execution.recorded` event into the signed Spine. Startup or operator
code can explicitly call reconciliation after a failure at any of those
boundaries; it recognizes an already committed exact event without duplicating
it and rechecks established anchors against a lock-consistent, signature-
verified Spine snapshot. The semantic uniqueness check and append execute
under the same Spine lock, closing the gap between verification and reading.
The protocol kernel does not start threads. The Web runtime invokes bounded
startup reconciliation and its lifecycle-owned recovery worker advances local
execution-audit pages; callers embedding the kernel directly must schedule
reconciliation themselves.

Execution Receipt federation uses two additional signed v1 envelopes. A
`TradeExecutionReceiptDelivery` binds the exact Receipt and Order digests,
sender DID, counterparty DID, destination, nonce, and a short validity window.
Before disclosing that envelope, the sender issues a fresh 256-bit challenge
to the destination identity-card endpoint. The signed card must echo the
challenge and the Order counterparty DID over the same DNS-pinned IP used for
the Receipt POST; a stale replay therefore cannot authorize disclosure.
This is freshness and destination-mismatch protection, not encryption or
cryptographic channel binding: a live relay can forward a challenge. Operators
must use authenticated HTTPS for untrusted networks and must not place
confidential material in the v1 envelope. Recipient-key encrypted delivery is a
future protocol extension rather than an implied property of this transport.
The receiving node must already retain the accepted Order and must re-run the
Receipt under explicitly configured local Rule, Adapter, content, and schema
policies before writing the Receipt through the normal CAS/Spine coordinator.
It then returns a counterparty-signed
`TradeExecutionReceiptAcknowledgement` bound to the delivery digest, Receipt
digest, receiver DID, and the receiver's local Spine event ID.

The sender persists the signed delivery and exact Order in a process-safe
SQLite outbox before network I/O. A verified acknowledgement is persisted
before the local `trade.execution.receipt-acknowledged` Spine projection, and
startup reconciliation repairs an interrupted projection or pending cleanup.
Only an expired delivery may be renewed; renewal preserves the Receipt,
Order, parties, target, and prior delivery digests while creating a new signed
nonce and validity window. UI and REST history expose `local-only`, `pending`,
`acknowledged`, or `unavailable` transport state without exposing operation
input or result content.

The acknowledgement means only that the named peer claims it retained and
locally policy-verified the signed claim at the referenced audit event. It does not
prove delivery quality, asset transfer, payment, legal acceptance, global
availability, or objective truth. Receipt intake remains unavailable until an
operator explicitly configures the receiver's local execution policies and
resolvers; signed remote data never supplies those trust decisions.

A Receipt counterparty may issue a Trade Receipt Review v1 after independently
replaying the Receipt under its own Rule and Adapter policies. The Review binds
the exact Order, execution ID, Receipt digest, reviewer DID and role, and the
digests of both local policy snapshots used for verification. Only the Order
party opposite the executor may sign. Decisions are `accepted`, `rejected`, or
`disputed`; negative decisions require at least one bounded machine-readable
reason code. An `accepted` decision is valid only for a Receipt whose claimed
outcome is `succeeded`.

A Receipt Review remains a signed counterparty claim. It proves neither that
delivery objectively occurred nor that goods, rights, or funds changed hands.
It does not close a dispute or grant reputation by itself. Local publication
first prepares a bounded write-ahead record containing the exact signed Review,
Receipt, Order, reviewer Rule Policy, and Adapter Policy bytes. The policy
snapshots are content-bound to the Review digests and reviewer policy in the
Order, so a later local policy rotation cannot change or strand first delivery.
It then stores the Review in a conflict-retaining CAS and projects one exact,
idempotent `trade.receipt.reviewed` event into the signed Spine. Startup or
operator reconciliation can repair an interrupted projection from the outbox
without requiring the caller to resubmit any of those objects. The local audit
outbox v3 stores `first_observed_at_ms` independently from mutable creation and
workflow-update timestamps. Normal publication must supply that local
observation explicitly and never derives it from the Review author's clock.
Legacy v1 outbox records are upgraded only when both currently available policy
bytes match the signed Review and Order bindings exactly. Legacy v2 records
remain readable and upgrade without changing their inferred observation time.
Creating a v1 record is available only through the explicitly named legacy
migration methods.

Contradictory signed Reviews sharing one semantic Review ID are retained as
equivocation. They never replace the first `trade.receipt.reviewed` event.
Instead, the coordinator appends an idempotent
`trade.receipt.review.conflicted` event that binds the primary and candidate
Review digests and reports whether both signed candidates were retained. A
marker-only conflict can be completed after configured capacity is increased.
Retention is complete only when the primary and marker digests are distinct
and both candidates are actually present. A conflict event proves that
inconsistent signed claims exist; it does not establish which claim is true.

Receipt Review federation uses its own signed v1 Delivery and Acknowledgement
envelopes. The Delivery is signed by the reviewer and binds the exact Order,
Receipt, Review, reviewer policy snapshot, Adapter policy snapshot, destination,
nonce, and short validity window. The reviewer policy must byte-match that
party's policy inside the accepted Order; a receiver never substitutes its own
policy for the reviewer's signed claim. Before sending, the sender performs the
same fresh challenge and DNS-pinned peer-DID check used by Execution Receipt
delivery. The executor node must already retain the Order and Receipt, then
independently replays the embedded Review under those signed policy snapshots
before writing it through the normal conflict-retaining Review CAS and Spine
coordinator.

Only after CAS retention and the exact local `trade.receipt.reviewed` anchor
does the executor sign a `TradeReceiptReviewAcknowledgement`. The ACK binds the
Delivery, Review, Receipt, Order, receiver DID, and remote Spine event ID. The
reviewer persists Delivery state before network I/O and persists a verified ACK
before its local `trade.receipt.review-acknowledged` projection. Startup and
operator reconciliation repair interrupted ACK anchoring or pending cleanup;
only an expired Delivery may be renewed, and prior Delivery digests remain in
generation history. A Review ACK means only that the peer claims it retained
and replayed the signed Review. It proves neither the Review's truth nor
delivery quality, payment, settlement, filesystem state, or legal acceptance.
The ACK `received_at` is the receiver's durable first v2 observation time, not
the Review author's earlier `reviewed_at`; exact Delivery replays reuse it.

### Dispute statement kernel

A `disputed` Trade Receipt Review is the signed opening fact for a dispute; the
protocol does not create a second, redundant open-dispute signature. Later
party claims use `TradeDisputeStatement` v1. Each statement binds the exact
Order, Execution Receipt, disputed Review candidate, author DID and Order role,
creation time, reason codes, and bounded content-addressed references. Its
stable case ID is derived from the Review's semantic `review_id`, so conflicting
signed Review candidates remain in one case; `review_digest` still pins the
exact candidate answered by a statement. The statement ID is content-derived
from the statement body. Parent statement digests form an
append-only DAG so offline peers can issue concurrent claims without a central
sequence allocator. A `response` must be signed by the Receipt executor;
`evidence` and `remedy-proposal` statements may be signed by either Order party.

Responses and remedy proposals carry a distinct typed `claim` reference;
supporting `evidence` remains a separate sorted list. Each claim or evidence
item is limited to 16 MiB of declared content and one statement may declare at
most 64 MiB of evidence. These are declarations, not fetched inline bytes.

An optional `rule_action` selects a Rule ID, exact Package digest, hook name,
and hook version. The Rule ID and Package digest must already occur in the
signed Order bindings. Creating or publicly verifying a statement with this
selector requires an exact-digest Package resolver and an exact matching hook
contract. Offline transport may use the explicitly distinct
`UnresolvedTradeDisputeStatement` type, which still verifies the statement
signature and Order/Receipt/Review bindings but cannot be mistaken for a fully
resolved statement. Converting it to `TradeDisputeStatement` requires the
exact-digest resolver. Resolvers return only immutable `RulePackage` values
created by the package verifier/store; raw mappings and duck-typed objects are
rejected at this trust boundary.
The selector is non-executing: a receiver must still apply local recognition
and Adapter policy and obtain any separate authority required before execution.

The signature proves authorship and binding, not truth. Evidence digests prove
only which bytes were referenced, not that those bytes support a claim. A
standalone statement also does not prove that every parent exists, that the DAG
is complete or acyclic, or that a remedy was accepted. Those properties require
an explicit projection over a bounded local snapshot.

The local dispute store retains only fully verified canonical statements under
their complete content digest. It is bounded by statement count and bytes,
serializes writers across processes, tolerates its own crash-temporary files,
fails closed on unknown layout entries, and requires the exact signed Order,
Receipt, Review, and any Rule Package resolver again on object read. Direct
digest reads verify only the requested object; explicit reconciliation reports
unrelated corrupt objects without turning them into global read outages. Each
write rescans only filenames and file sizes before enforcing capacity; it
does not reparse every retained statement. This keeps the byte boundary correct
after out-of-band file changes without restoring the earlier full-JSON O(N)
write path. A successful write means only that this node retained those signed
claim bytes. Statement pages use snapshot-bound cursors. If a signed statement
arrives while a caller is walking pages, continuation fails explicitly and the
caller must restart from page one; a changing collection is never silently
presented as a complete snapshot. Paging performs a bounded read and complete
content-digest check for every content-addressed file, but caches the canonical
header instead of reparsing the full JSON collection on each page. The selected
page is reread while the store lock is held, then fully protocol-validated after
that lock is released so a Rule Package resolver cannot invert lock order. The
cache therefore reduces parse and memory cost without making mtime or an
unsigned index an integrity authority.

`TradeDisputeGraphProjection` is a deterministic, unsigned local view over one
exact disputed Review. It rechecks every retained Statement content digest and
protocol binding, distinguishes unavailable parents from exact parent content
that names another Review, permits only the protocol's bounded clock skew when
checking parent/child chronology, propagates incomplete or invalid ancestry,
and exposes a `v2:<64-lowercase-hex>` snapshot token, roots, tips, and
deterministic topological order. The token binds the Review, dispute, exact
retained Statement digest set, and every known cross-Review parent binding that
can change the graph verdict; it is versioned protocol metadata rather than a
`sha256:` content reference.
Federated intake may retain a child before its parent so offline delivery can
converge; the projection remains `incomplete` until the exact parent arrives.
Local creation is stricter: before any durable idempotency reservation or claim
write, a Statement that extends parents walks only its content-addressed
ancestor closure and rejects missing or invalid ancestry. The write path repeats
that check as defense in depth. Both the ancestor walk and complete projection
have independent node and aggregate-edge budgets. Unrelated corrupt statements
therefore remain visible to explicit reconciliation without blocking a valid
local parent chain. The potentially O(N) complete projection has a dedicated
authenticated endpoint and is not recomputed by paginated Statement listing.
Its HTTP projection returns full counts but bounds each detailed list to 500
entries; the in-process protocol API retains the complete bounded projection.
Operational Rule Package resolver failures are retryable dependency failures,
not claim-integrity verdicts.

`complete` means only structurally complete in this local snapshot; it
does not mean globally complete, truthful, admitted, or adjudicated.

The optional Spine projection emits `trade.dispute.statement.retained` after
the CAS write. Its exact payload binds the statement and labels it
`signed-claim-not-adjudicated`. The event signature, payload, and observation
time are independently verifiable. Intake additionally requires that the
Spine event signer is the local Delivery receiver; an older matching anchor
from another DID is rejected rather than reused. Spine failure leaves a recoverable CAS
statement; exact-digest reconciliation can add the missing idempotent anchor
later. The anchor time is the time that retention was audited, not necessarily
the first time any process saw the statement.

Federation uses a destination-bound `TradeDisputeStatementDelivery` v1 signed
by the statement author. It embeds the exact signed statement and binds its
Order, Receipt, Review, statement digest, opposing Order party, nonce, creation
time, and short expiry. The receiver verifies the envelope before durable
observation, then resolves the statement against the exact Package, writes the
content-addressed statement, emits the claim-not-fact Spine anchor, and signs a
`TradeDisputeStatementAcknowledgement`. The ACK binds the complete Delivery,
all four artifact digests, the receiver, the receiver's first durable
observation time, and the remote Spine event ID. It asserts only
`retained-claim-not-adjudicated`. The event ID is a signed reference, not proof
that the remote event is available; that requires separate Spine evidence.

The sender persists the signed Delivery before network I/O and uses a bounded,
crash-recoverable SQLite send lease so concurrent operator retries cannot issue
duplicate outbound requests. Expired envelopes may be replaced only after the
stored generation is cryptographically verified as expired; every superseded
Delivery digest remains in the local generation history. A verified remote ACK
is persisted before the sender emits
`trade.dispute.statement-acknowledged`. That local event binds the Statement,
current Delivery, ACK, receiver, remote event reference, generation, and all
superseded Delivery digests. Startup and lifecycle recovery can idempotently
complete a missing local anchor without sending the claim again.

The domain-separated signing inputs use the exact ASCII prefixes
`nth-dao/trade-dispute-statement-delivery/v1` and
`nth-dao/trade-dispute-statement-acknowledgement/v1`. Agreement v1 publishes
the canonical bytes and complete signing-input bytes for both envelopes.

The intake journal is a bounded, cross-process SQLite state machine. It stores
the canonical Delivery before Package resolution, advances through observed,
anchored, and acknowledged states, and preserves a receiver-signed first
observation attestation across restart. The attestation binds the exact
Delivery digest, Delivery ID, recipient DID, and timestamp; an unsigned local
row cannot manufacture a timely first observation. Exact replay can therefore
resume after the network envelope expires without pretending that a late first
delivery was timely. Unsigned non-empty legacy journals and tampered or
schema-incompatible rows fail closed.

Acknowledged hot rows may be atomically moved to a verified archive so the
bounded intake table can continue accepting work. Archive reads preserve exact
ACK replay and all signed bindings. Purge is explicit, bounded, returns every
removed Delivery digest to the caller, and is ineligible until the later of
archive time, first observation, or signed Delivery expiry plus the protocol's
maximum clock skew, followed by the configured retention period. Observed and
anchored rows cannot be archived or purged. This is a programmatic protocol
boundary; public HTTP dispatch, maintenance scheduling, rate limiting, and peer
admission policy still belong to the later federation service layer.

The Spine writer uses a signed write-ahead append intent. Recovery accepts only
an exact byte prefix of the intended canonical event extending a fully verified
chain prefix and authored by the configured log signer. A partial tail without
that intent, a foreign signer, or conflicting bytes remains a hard integrity
failure. Dispute Delivery TTL and receiver clock-skew policy inputs are capped
at 86,400 seconds in both Python and TypeScript before nanosecond conversion.

The signed bilateral Fetch Request/Response v1 wire kernel can authorize one
Order party to request one exact Statement digest from the opposing party. The
Request binds the Order, Receipt, disputed Review, dispute, destination, nonce,
and short lifetime. The responder-signed Response binds the complete signed
Request digest and embeds the original author-signed Statement. The bounded
SQLite Fetch journal atomically consumes `(requester_did, nonce)`, retains
nanosecond-precise chronology, and separates reservation from an expiring
single-owner processing lease. Failed lookup establishes a durable retry floor;
global and per-DID record/pending quotas isolate authenticated storage use. One
exact signed Response is retained for idempotent replay with content-rebinding,
byte-accounting, schema-constraint, and lease-owner checks. The response is
returned only after a recoverable `trade.dispute.statement.fetch.served` Spine
projection binds the Request, Response, Statement, parties, and `served_at`.
A completed but unanchored response remains repairable and cannot be purged.
Other cleanup becomes eligible only after signed expiry plus configured clock
skew. Journal records must be resolved against the signed Order/Receipt/Review
again before use. Public HTTP exposure, body limits, network rate limiting,
peer admission, automatic cross-node parent retrieval/import, governance
admission, and adjudication remain future work. The responder coordinator
performs context replay, freshness and destination admission before nonce
reservation, then permits only the lease owner to retrieve, sign, persist, and
audit the response. Transport timestamps are restricted to the signed 64-bit
nanosecond range used by the durable SQLite state; out-of-range RFC3339 values
fail at the protocol boundary rather than during persistence. The coordinator
may coalesce verification of byte-identical immutable signed inputs in a
bounded in-memory cache. Destination and lifetime checks still run for every
observation. Verified audit reuse is bound to the content-aware Spine storage
token, so any
on-disk change or cross-process append invalidates the cached snapshot and
forces chain and event verification again. Local DAG completeness,
chronology, and non-DAG detection are explicit derived checks, but no Statement,
Delivery, ACK, Fetch document, journal row, or retention anchor settles a
dispute, changes reputation, transfers an asset, or authorizes funds. JSON
Schema validates wire shape; the protocol validator remains mandatory for
signatures, identifiers, roles, chronology, resource bounds, destination,
replay handling, and artifact bindings.

The requester uses a separate bounded SQLite outbox. It persists the exact
canonical signed Request before transport, reuses those bytes for concurrent
and restarted retries, and creates a new retained generation only after the
previous Request has signed expiry. A verified Response and standalone signed
audit are committed before success is returned, allowing exact offline replay
after restart. This is durable transport evidence, not Statement import or
proof that the remote audit is included in the responder's full Spine. The
public route verifies the bounded Request envelope, destination, lifetime, and
signature before reading Order, Receipt, or Review state. Missing and
unauthorized trade context share one unavailable response to avoid exposing a
context-existence oracle. Web runtime coordinator retention is capped at eight
idle-pruned coordinators; each coordinator's immutable verification, response,
and audit caches have a five-minute TTL and a two-MiB aggregate canonical-byte
bound.

Trade Execution Adapter Policy v1 is a canonical protocol value with kind,
protocol version, accepted Adapter digests, execution modes, and permissions.
Its digest is computed over that exact canonical representation. Receipt
Reviews bind this public Policy digest rather than a Review-private encoding.

A later contradictory Receipt blocks the audit record even when its first
candidate was already anchored. Blocked is not trusted as a local status flag:
reconciliation must prove that Receipt CAS retains a distinct candidate marker,
that the original Receipt digest remains present, and that any recorded
event ID matches the exact Spine anchor. Reconciliation uses one stable
execution-ID cursor and applies its limit across prepared, stored, anchored,
and blocked records. Persisted update time is a monotonic floor so wall-clock
rollback cannot strand an otherwise valid recovery.

The CAS retains the first contradictory signed candidate and records a durable
conflict marker before capacity checks, so later reads fail closed even if the
full candidate cannot fit. `conflict_status()` exposes the marker digest,
retained Receipt digests, and whether retention is complete. This makes local
Receipt publication and Spine projection recoverable and idempotent; it does
not make an Adapter's external effects exactly-once, prove the claim true, or
create a cross-node settlement ledger. Delegation, sandboxed Adapter
execution, and transactional side-effect outboxes remain separate reviewed
slices.

The v1 execution Spine payload contains only protocol version, execution and
Receipt digests, Order identity and digest, executor DID, operation ID,
outcome, and completion time. Receivers must bind it back to the exact signed
Receipt and Order; schema-valid fields alone are not evidence that execution
succeeded.

`nth_dao.execution_receipt.ExecutionReceipt` is a different wire protocol for
an Agent's generic goal timeline. A Trade Execution Receipt is specifically
bound to a bilateral Trade Order, operation grant, Rule Hook, and Adapter
policy. The two signed objects have different purposes and are never
implicitly converted.

The Agreement conformance vector uses deterministic public test keys and
contains the exact Offer, Proposal, Proposal Delivery, receiver-signed intake
receipt, Acceptance, Order, Rule Package and
resources, verifier and Adapter policies, Adapter artifact, execution content,
expected readiness, execution Receipt, content digests, destination-bound
Execution Receipt delivery, and receiver-signed acknowledgement. Delivery
vectors also specify recipient, verification time, TTL, clock skew,
wrong-recipient, expiry, future-time, acknowledgement-binding, and tamper
outcomes so another implementation must exercise wire semantics rather than
only parse a signature. Those keys must never be reused or trusted.

## Adapter Runtime (v1, Slice B)

The first execution surface for mode `adapter` is
`nth_dao.trade_rules.adapter_runtime.SubprocessAdapterRunner`: it runs one
approved, digest-pinned adapter artifact as a separate local process speaking
`nth-trade-adapter-rpc/1` — a minimal, MCP-shaped JSON-lines protocol over
stdio (initialize-with-digest handshake → hook invocation → result; the
message shapes follow MCP's initialize/tools-call pattern without importing
any MCP SDK).

Boundaries that are deliberate:

* The runner is a pure hook executor and is disabled by default. A host must
  explicitly set `allow_unsafe_local_execution=True` for reviewed local code.
  Bilateral consent, readiness,
  permission scoping, and schema validation stay in
  `TradeExecutionCoordinator.issue`; the runner adds an administrative process
  boundary, concurrency gate, wall-clock termination, bounded stdio, a fresh
  cwd, `python -I`, a minimal environment, and artifact digest verification
  before every spawn.
* None of those controls is an OS or capability sandbox. An enabled artifact
  can read user files, use the network, start subprocesses, and consume CPU or
  memory with the NTH DAO process's authority. Permission tokens declare intent
  for policy and receipts; they do not enforce access. Community artifacts must
  use a separately sandboxed executor (for example `sandboxed_wasm`) before they
  can be treated as confined.
* A hook that runs and reports `ok:false` yields `outcome="failed"` with a
  `{"error": ...}` problem payload (no output-schema validation, per the
  receipt rule that only successful results are schema-checked).

## Compatibility

Existing Commerce v1 remains a separate compatibility profile:

```text
org.nthdao.legacy.single-paid-digital-service/1
```

Its signed wire format is not rewritten in place. Trade Rule Protocol v2 is
introduced through new modules and explicit versioned objects. Commerce v1's
`IntentMandate -> CartMandate -> PaymentMandate -> Order` path remains the
compatibility and payment-oriented profile for the existing single paid
digital-service flow. Trade Agreement v1 is the broader exchange agreement
profile for barter, product-for-service, asset swap, and future Rule-defined
transactions. The two profiles are not silently converted into one another.

## Security Invariants

No Rule Package or Adapter may disable:

- signature and principal authority checks;
- exact digest binding;
- nonce and TTL replay protection;
- object and package resource limits;
- append-only event integrity;
- local execution permissions;
- private-key isolation;
- idempotency for side effects;
- signed Receipts;
- fail-closed required-rule negotiation.

## Delivered Protocol Slices

The reviewed protocol kernel currently contains:

- Rule Manifest v1;
- Trade Offer v2;
- NTH Trade Canonical JSON v1 validation;
- signing and verification;
- signed content digests;
- append-only local Offer storage and deterministic revision projections;
- content-addressed, non-executing Rule Package storage;
- bounded Rule Package Bundle v1 federation for exact live-Offer dependencies,
  with operator-directed, Order-bound, reverified cache import and explicit
  non-trust/non-execution semantics;
- explicit local recognition policy and bounded exact-digest dependency
  resolution;
- signed, sequence-linked local Recognition policy revisions with deterministic
  controller rotation, content-addressed rollback-detecting persistence,
  recoverable `trade.rule.recognition.policy.updated` Spine projection, and
  fail-closed advisory Web v2 evaluation;
- signed, sequence-linked Rule Recognition v1 statements and deterministic
  scoped local quorum projection, bounded expiry, durable CAS import, and
  metadata-only invalid-input quarantine, plus recoverable exact-digest
  `trade.rule.recognition.recorded` Spine anchoring and cross-log validation,
  without automatic execution authority or claims of globally fresh
  revocation;
- canonical Offer-head and policy-snapshot binding before Order-facing rule
  resolution;
- signed bilateral Proposal and Acceptance statements with independent local
  policy snapshots, exact policy digests, and strict local time limits;
- destination-bound, short-lived DID-signed Proposal delivery with per-source
  and aggregate budgets, independent receiver replay, bounded cross-process
  CAS retention, restart reconciliation, and an explicit
  `retained-unaccepted` operator view;
- deterministic, self-verifying Order snapshots containing the exact signed
  Offer, Proposal, and Acceptance;
- bounded, cross-process-safe Order CAS caching with retained equivocation
  candidates, bounded reconciliation, and explicit non-audit semantics;
- bounded write-ahead Order audit records with recoverable CAS persistence,
  exact idempotent `trade.order.accepted` Spine anchoring, and cross-log
  validation;
- execution-time transitive Rule Package re-resolution under both signed
  party policies and a mandatory current executor policy;
- signed, content-addressed Trade Execution Receipt v1 claims with deterministic
  per-Order/per-operation/per-executor identity, strict party-role and
  operation-grant binding, content-addressed Adapter resolution, and
  conflict-retaining local CAS storage;
- bounded write-ahead execution-audit records with recoverable Receipt CAS
  persistence, exact idempotent `trade.execution.recorded` Spine anchoring,
  verified-snapshot replay, bounded cursor reconciliation, and externally
  checked fail-closed equivocation state;
- destination-bound signed Execution Receipt delivery, mandatory counterparty
  policy replay, receiver-signed acknowledgement, durable sender outbox,
  restart reconciliation, expired-envelope generation history, and explicit
  non-settlement UI projection;
- counterparty-signed Trade Receipt Review v1 claims with mandatory local
  Receipt replay, exact policy snapshot binding, conflict-retaining CAS
  storage, write-ahead restart recovery, and idempotent
  `trade.receipt.reviewed` / `trade.receipt.review.conflicted` Spine
  projections;
- destination-bound Receipt Review delivery with signed reviewer policy
  snapshots, mandatory executor replay, receiver-signed ACK, durable sender
  outbox, restart reconciliation, expiry-only renewal history, and explicit
  claim-not-truth UI semantics;
- signed, content-addressed Trade Dispute Statement v1 claims with bounded
  parent/evidence references, destination-bound Delivery and receiver ACK,
  durable sender/intake recovery, claim-not-fact Spine projection, and an
  explicit local DAG completeness/chronology projection that does not
  adjudicate truth; the operator response returns both signed transport
  documents so the browser can independently verify Delivery content
  addressing, both Ed25519 signatures, ACK digest, and exact response binding;
- a destination-bound, short-lived Dispute Statement Fetch Request/Response v1
  protocol kernel for one exact missing Statement digest, with bilateral Order
  authorization, complete signed-request binding, responder provenance, and
  embedded author-signature replay, plus a bounded atomic SQLite nonce/response
  journal, single-owner processing lease, per-DID quotas, durable retry floor,
  and recoverable signed Spine disclosure audit in the
  verify-reserve-claim-lookup-sign-complete-anchor responder coordinator;
- a bounded network Fetch service exposing that coordinator through an
  anonymous-but-cryptographically-authorized federation endpoint, plus a
  console-authenticated requester endpoint that DNS-pins the peer, verifies a
  fresh challenged identity card against the requested responder DID, sends the
  signed Request, and independently verifies the signed Response and remote
  audit binding before returning it; a bounded durable requester outbox retains
  exact Request generations and commits the verified Response and audit before
  success, supporting restart-safe exact retry and offline replay. Requester-side
  fetch does not implicitly import the Statement or adjudicate its claim, and a
  standalone signed audit event does not prove inclusion in the responder's
  undisclosed full Spine. The shared verified-peer transport performs a fresh
  challenged identity-card check and a deadline-bounded POST on the same pinned
  address. Conformance tests exercise two independent workspaces over a real
  loopback HTTP connection and responder restart replay;
- bounded package-store reconciliation with explicit cleanup;
- authenticated, paginated local Trade Skill catalog inspection with strict
  frontend response validation, metadata-only resource projection, and
  explicit non-recognition/non-execution semantics;
- strict local operator APIs for signed publish, paginated chain listing, and
  exact digest retrieval;
- user-directed durable import of a reverified federated Offer into the local
  append-only Offer Store, including every revision in the bounded, complete
  disclosed chain, with signed remote-publisher identity inside each Offer and
  exact local-importer provenance in each Store/Spine anchor,
  including the reverified signed discovery announcement and content-derived
  federation key; signed write-ahead import proposals, cross-process digest
  serialization, restart-safe idempotent completion anchoring, and explicit
  non-trust/non-acceptance semantics;
- schemas and deterministic positive and negative conformance vectors,
  including Agreement v1, Proposal Delivery v1, Execution Receipt v1,
  Execution Receipt Delivery/Acknowledgement v1, Receipt Review v1, Receipt
  Review Delivery/Acknowledgement v1, Dispute Statement Fetch
  Request/Response v1, Dispute Statement creation reservation and
  creation-failure audit payloads, first-page/graph snapshot binding,
  cross-Review parent-context token separation, and the
  `trade.order.accepted`, `trade.execution.recorded`, and
  Rule Recognition, Recognition Policy, and Receipt Review audit payloads;
- focused tests.

Agreement and Order objects remain protocol-kernel primitives. The audit
outbox makes local Order persistence and Spine projection recoverable, but it
does not make separate files atomically committed and it is not a settlement
ledger. Federation can now discover an exact signed Trade Offer v2 through a
short-lived signed exchange hint, a bounded head-proof bundle, and strict
verification of the complete disclosed chain from revision 1. The
projection exposes only a local publisher's active canonical Offer head, but a
signature still proves authorship rather than truth or global freshness.
The discovery hint has a hard 24-hour lifetime and cannot outlive its Offer;
renewal requires a new publisher signature.

Local Dispute Statement authoring validates the complete bounded parent chain
before it writes an idempotency reservation. The signed
`trade.dispute.statement.create.reserved` event binds the author, request
digest, and logical creation time. If work after that reservation fails, the
node appends an idempotent
`trade.dispute.statement.create.attempt-failed` event. Its content-derived
failure ID binds the operation, exact request, and a closed reason code;
retryability is derived from that reason code rather than chosen by an API
caller. This event records an unsuccessful attempt, not a terminal judgment:
the same reserved operation may complete after a retryable dependency recovers.
Store graph projection applies statement, byte, node, and edge limits before
full statement verification wherever a validated index header is sufficient.
The public Agreement vector fixes the reservation derivation inputs, the
closed reservation payload, one paginated Store snapshot, its full graph
projection, and distinct `incomplete` versus cross-Review `invalid` parent
cases. Page and graph tokens must match only when they describe the same exact
statement inventory, graph-affecting parent context, and effective
microsecond-resolution clock-skew policy.

Globally convergent latest-revision proofs, Acceptance federation, automatic
missing-parent import, inventory or asset
reservation, fulfillment, payment, global Receipt/Review propagation,
delegation, and sandboxed
executable Adapters remain separate, independently reviewed slices. Durable
remote retention preserves the complete chain disclosed by one signed,
short-lived publisher head claim; it does not prove that the publisher did not
withhold a later revision. Trade Offer discovery, Rule Package
loading, Agreement creation, Order storage, and Receipt creation cannot execute
settlement.

## Deferred Repository Quality Sweep

The repository-wide Ruff baseline recorded on 2026-07-29 contains 319
historical findings, primarily in legacy examples and tests. Files changed by
the reviewed trade slices pass their focused Ruff gate. After the transaction
framework reaches its planned protocol boundary, run a dedicated cleanup
series that:

1. freezes and publishes the Ruff configuration used for the baseline;
2. fixes findings by module in reviewable commits, without mechanical behavior
   changes;
3. reruns each affected module's tests after every batch; and
4. makes repository-wide Ruff success a required merge gate.

`DecisionStore` initialization now serializes SQLite journal negotiation and
schema DDL across processes. Its concurrency regression also uses bounded
barrier and join waits, so a worker failure is reported instead of hanging the
suite.

# NTH DAO Intent Plane

Status: protocol boundary; execution is intentionally deferred until the
plugin kernel and deterministic policy gate are stable.

The first boundary implementation is `org.nth-dao.intent.resolve` v1. It has a
closed request, unsigned `IntentDraft`, response semantics, canonical
content addresses, and checked-in cross-language vectors. The distribution
includes `org.nth-dao.intent.literal-resolver`, an offline reference plugin
which is installed disabled, requests no permissions, performs no semantic
inference, and always requires clarification. It exists to verify the plugin
boundary, not to claim natural-language understanding.

## Principle

An intent is a request to explore possible outcomes. It is not authority to
act. A model may interpret language and propose alternatives, but only a
deterministic policy gate and an explicit signed authorization can cross an
irreversible boundary.

The generic intent plane does not replace the existing transaction
`IntentMandate`. The former is a reviewed draft and proposal process; the
latter delegates transaction authority and remains part of the signed
Intent/Cart/Payment mandate chain.

## Flow

```text
human or agent input
  -> unsigned IntentDraft
  -> clarification and visible diff
  -> signed IntentEnvelope
  -> one or more SolverProposal objects
  -> deterministic policy evaluation
  -> explicit proposal selection
  -> Task / Mission / Agreement
  -> transaction Mandates when required
  -> prepare / authorize / commit
  -> Receipt or Dispute
```

## Required Properties

### IntentDraft

- unsigned and visibly non-authoritative;
- records source text, assumptions, ambiguity, and requested clarification;
- has bounded, digest-addressed attachment claims whose bytes and declared
  sizes remain explicitly `unverified` at the resolver boundary;
- cannot be submitted directly to an executor.
- binds the exact resolve request digest and preserves source text and
  attachment metadata without rewriting them.

An `IntentDraft` with `authority=none`, `commit_authority=false`,
`executable=false`, and `review_required=true` is an untrusted hint. Its fixed
`format=org.nth-dao.intent-draft` selects the v1 schema without granting it
authority. During a live invocation the Host knows which reviewed plugin
produced the response.
The response binds a Host-derived invocation-context digest covering plugin ID,
capability ID, invocation ID, and principal scope. The Host independently
checks it after output and exchange validation, so a cached response from
another invocation or principal is rejected. Raw principal text is not emitted.
Once detached, `resolver_id` is only a self-declared label and the digest is
only a content address; neither proves provenance, truth, or authorization.
Promotion requires a separate signed `IntentEnvelope`; changing any
source field requires a new resolve request and draft. `source_kind` is also a
request classification, not verified human, agent, or system identity.

### IntentEnvelope

- signed by the human, agent, or delegated authority accepting the draft;
- binds the accepted draft digest, scope, constraints, expiry, and nonce;
- names allowed solver classes but grants no commit authority;
- is append-only; revisions create a new envelope linked to the prior digest.

The v1 wire primitive is now implemented in
`nth_dao/plugins/intent_envelope.py`; see [Intent Envelope v1](INTENT_ENVELOPE.md).
It is Host-owned protocol code, not a signing capability offered to plugins.
It verifies a direct Ed25519 DID acceptance against explicit local expectations.
Its pure functions do not persist acceptance or consume nonces. A separate
[local acceptance journal](INTENT_ACCEPTANCE.md) now provides atomic revision
and nonce checks, restart-safe idempotency and local audit observations. A signed
predecessor hash alone still does not establish a current head. An explicit
[Spine bridge](INTENT_ACCEPTANCE_SPINE.md) can project hash-only historical
observations with node signatures and crash-safe retries. Governance policy
integration, cross-node acceptance and business promotion remain deferred.

### SolverProposal

- identifies solver DID/plugin and input intent digest;
- separates facts, assumptions, estimates, risks, and requested permissions;
- binds evidence by content hash and source provenance;
- remains a claim, not a verified fact;
- can be rejected, refuted, or superseded.

The first closed solver boundary is now implemented as
`org.nth-dao.intent.propose` v1; see [Intent Solver Proposal v1](INTENT_SOLVER.md).
It requires a valid signed Envelope plus exact Host bindings to the local
acceptance audit, governing policy snapshot, idempotency key, and
content-addressed evidence. The shipped review-only provider is installed
disabled and performs no inference. Its output remains unsigned,
non-executable, unverified, and selection-required.

### PolicyDecision

- produced by deterministic code, not a language model;
- records the policy version and every evaluated constraint;
- fails closed on unknown fields, unsupported assets, missing evidence, or
  ambiguous authority;
- cannot create permissions absent from the signed intent or host policy.

## Automation Levels

| Level | Behavior | Human interface |
| --- | --- | --- |
| `A0` | Observe and summarize only. | Optional display. |
| `A1` | Draft intents and proposals. | Review required. |
| `A2` | Execute reversible local actions. | Notification and undo window. |
| `A3` | Prepare external actions. | Explicit authorization required. |
| `A4` | Commit bounded recurring actions under a signed mandate. | Persistent control, limits, and revocation UI required. |

No profile or plugin may raise an automation level beyond the signed mandate
and host policy. High-risk authorization, exceptions, governance, and disputes
must remain inspectable even if routine low-risk flows become UI-light.

## Threat Model

- prompt injection inside source text or retrieved content;
- solver collusion or correlated model errors;
- stale evidence and changed external prices/state;
- confused deputy between intent, mandate, and executor;
- hidden permission expansion by a plugin;
- replay of an old accepted intent;
- a truthful signature over a false claim.

Mitigations include provenance labels, content-addressed evidence, nonce/TTL,
fresh deterministic checks before commit, independent solver options, bounded
capability grants, signed receipts, and a first-class dispute path.

## Current Boundary

Implemented now:

- closed v1 input, draft, and output semantics; resolver business errors are
  not defined, while schema and lifecycle failures remain Host boundary errors;
- exact request/source/attachment exchange binding;
- Host-owned request snapshots and isolated, mutation-checked JSON arguments
  for every validation callback;
- Host-verified response invocation-context binding, without claiming detached
  signature or provenance guarantees;
- attachment metadata remains an unverified claim until a separate Host-owned
  artifact boundary validates the referenced bytes;
- canonical JSON, SHA-256, authority, and source-binding vectors verified by
  Python and Node, with both consumers checking the current closed schema
  subset and operation-specific semantics; the Node consumer validates unused
  schema branches too, rejects unsupported keywords, and does not claim general
  JSON Schema support;
- a bounded, offline, zero-permission literal reference provider;
- Host lifecycle registration with no automatic authorization or enablement.
- domain-separated, non-executable `IntentEnvelope` v1 signing and verification;
- exact draft/source-request binding, rejection of open clarifications and empty
  outcomes, and bounded solver selectors with no execution or capability grants;
- mandatory Host expectations for signer, audience, scope, draft, revision head,
  automation ceiling, and solver classes; strict time bounds;
- checked-in signed vectors, independent Node verification of Python signatures,
  Python verification of a Node-generated signature, and re-signed negative
  cases that must fail semantic checks despite valid cryptography.
- explicit Host SDK acceptance journal with one atomic artifact/nonce/audit
  write, current-context callback under the writer lock, bounded verified history,
  competing-revision rejection and restart-safe exact retries.
- opt-in, node-signed Spine observation anchors, with no raw source/context
  publication, bounded replay pages and idempotent crash recovery.
- a closed, immutable Host policy snapshot that binds one exact reviewed draft
  to direct member DIDs, roles, revocation state, solver/automation limits, and
  membership/revocation source digests; its content address is retained in new
  acceptance contexts.
- a closed, non-executable `SolverProposal` v1 capability with exact signed
  Envelope, acceptance-audit, policy, idempotency, Host authority, invocation,
  and evidence binding;
- checked-in Python/Node conformance vectors and a disabled, offline,
  zero-permission review-only solver reference provider.

Not implemented now:

- model-backed interpretation or solver providers, and deterministic proposal
  policy providers;
- automatic creation of Tasks, Missions, Agreements, Offers, or Mandates;
- capability grants, signing, payment, execution, or approval through a draft;
- UI promotion, visible acceptance diff, or persistent unsigned draft storage;
- automatic governance-source ingestion, delegation, cross-store locking,
  automatic audit publication or cross-node acceptance; durable proposal
  storage, signed detached solver provenance, proposal selection, refutation,
  supersession, or business promotion. Live
  business promotion remains disabled until these boundaries are integrated.

Those omissions are security boundaries. They must not be filled by routing a
draft directly into an existing executor.

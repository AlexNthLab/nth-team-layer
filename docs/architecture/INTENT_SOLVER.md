# Intent Solver Proposal v1

Status: protocol boundary and disabled offline reference provider. Business
promotion, policy selection, execution, and durable proposal storage are not
implemented by this capability.

## Purpose

`org.nth-dao.intent.propose` v1 lets a reviewed plugin propose how an already
signed and locally accepted `IntentEnvelope` might be satisfied. The output is
an unsigned `SolverProposal` claim for comparison and review.

The capability does not:

- decide whether a proposal is correct or acceptable;
- grant a capability, mandate, payment permission, or commit authority;
- create a Task, Mission, Agreement, Offer, or Order;
- persist or federate a proposal;
- select a proposal or execute an action.

Those omissions are deliberate boundaries. A later deterministic policy
decision and explicit selection operation must precede any business promotion.

## Host Invocation Binding

A `propose` request carries the canonical signed `IntentEnvelope`, its digest,
the local acceptance audit digest, the governing policy snapshot digest, and
optional invocation-materialized evidence. The caller must derive `InvocationAuthority`
from trusted local state:

```text
mandate_digest  = acceptance_audit_digest
idempotency_key = proposal_id
resource_ids    = {
  intent_envelope_digest,
  policy_snapshot_digest,
  every invocation-materialized evidence digest
}
```

The resource set is exact, not a subset check. A capability handle carrying
broader resource scope is rejected. `probe` accepts no mandate, idempotency key,
or resources.

These fields do not prove acceptance by themselves. The Host is responsible
for deriving them from a currently verified acceptance journal and policy
snapshot, and for supplying `proposed_at_ms` from a trusted current clock.
Copying digest strings or timestamps from an untrusted request is not
sufficient. Proposal validity must be rechecked when the proposal is later
displayed, selected, or promoted.

Application code should enter through
`prepare_governed_intent_solver_invocation()`. The builder reads the exact
accepted Envelope from `IntentAcceptanceStore`, requires it to remain the
current scope head, resolves the current policy from the same workspace,
rejects legacy ungoverned acceptance, checks both validity intervals against a
required trusted clock, and derives the request plus `InvocationAuthority`.
Its immutable result invokes a `ProviderBinding` without exposing a mutable
request/authority assembly step. The result is a one-use authorization ticket:
immediately before provider invocation it rechecks the verified acceptance
head, policy head, and trusted clock under the policy coordination lock, then
consumes itself before confidential evidence crosses the provider boundary.
A policy change after that linearization point does not cancel an already
in-flight call. Directly constructing request and authority objects is a
low-level test and protocol integration surface, not an application workflow.
The governed builder derives the invocation principal from the verified
Envelope `audience_did`; callers cannot supply a different attribution label.

The response binds a Host-derived invocation-context digest over plugin ID,
capability ID, invocation ID, principal, audit digest, idempotency key, and the
resource set. It prevents replay into another live invocation. It is not a
signature and gives a detached proposal no portable proof of provenance.

## Proposal Semantics

A v1 proposal has fixed boundary flags:

```json
{
  "authority": "none",
  "claim_status": "unverified",
  "commit_authority": false,
  "executable": false,
  "review_required": true,
  "selection_required": true
}
```

It separates facts, assumptions, estimates, constraints, risks, proposed
actions, and requested permissions. Facts and estimates reference explicit
evidence digests, and estimates also state their basis.

Requested permissions must be a subset of the accepted draft's requested
capabilities. This remains a request for later policy evaluation, not a grant.

`solver_plugin_id` is checked against the live Host plugin context. An optional
`solver_did` is only a self-declared label in v1 because the proposal is not
signed by that DID. Detached provenance requires a separate signed artifact in
a future profile. There is no separate response-level `solver_id`; such a field
would duplicate provenance without binding it to the Host plugin context.

## Evidence

Every evidence entry has a SHA-256 content address, media type, source kind,
source reference, observation time, provenance, and verification status.

Input `invocation-materialized` evidence also carries canonical Base64
material. The invocation boundary checks each content digest, limits one item
to 128 KiB and the aggregate to 256 KiB, and sends the bytes inside the
invocation. This preserves the
zero-effect contract: a Solver does not dereference a path or URL and receives
no ambient filesystem or network authority. The returned proposal strips the
material and preserves only the descriptor, so later storage does not silently
duplicate confidential source bytes.

| Provenance | Verification status | Meaning |
| --- | --- | --- |
| `accepted-envelope` | `signature-bound` | Exact draft bytes are bound by the signed Envelope. |
| `invocation-materialized` | `content-verified` | Inline bytes match the digest for this invocation; source metadata remains a claim. |
| `solver-observed` | `unverified` | The solver claims it observed content with this digest. |

`signature-bound` proves who signed the exact accepted bytes. It does not prove
that the draft, a fact, a root cause, or an external assertion is true.
`content-verified` proves only that the inline bytes match the digest supplied
to the invocation. It does not verify that `source_kind` or `source_ref` names
the true origin. Source authentication requires a future reviewed evidence
resolver capability. Policy and semantic correctness still require independent
evaluation.

The proposal must preserve every invocation-materialized descriptor exactly and contain
exactly one protocol-derived accepted-draft evidence item. Facts and estimates
cannot reference evidence absent from the proposal.

## Reference Provider

`org.nth-dao.intent.review-solver` is shipped as a disabled, zero-permission,
offline conformance provider. It performs no model inference or retrieval. It
copies accepted outcomes and constraints into a review-only proposal, requests
no permissions, and adds an explicit unverified-claim risk.

Enabling this provider demonstrates contract wiring only. It does not make the
proposal useful, correct, selected, persisted, or executable.

## Conformance

Checked-in files under `nth_dao/plugins/vectors/` freeze the capability, input,
output, proposal, protocol, and positive/negative wire cases. Python regenerates
and validates them. An independent Node consumer rechecks the closed schema
subset, canonical JSON, signed Envelope, authority, context, evidence, proposal,
and exchange bindings.

Wire JSON number tokens use decimal integer syntax only. Fractional, exponent,
negative-zero decimal, and values outside the interoperable safe-integer range
are rejected before a JavaScript parser can erase their lexical form. Raw JSON
vectors cover request, response, and embedded proposal boundaries.

The Node consumer is bounded conformance code, not a general JSON Schema
implementation or a production SDK.

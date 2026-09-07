'use strict';

// Independent bounded consumer of SolverProposal v1. This is conformance
// code, not a runtime SDK and not a general JSON Schema implementation.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { ed25519 } = require('@noble/curves/ed25519.js');

const vectorPath = process.argv[2];
if (!vectorPath) {
  process.stderr.write('usage: node intent_solver.cjs <intent-solver-wire-cases-v1.json>\n');
  process.exit(2);
}

class ValidationError extends Error {}
function fail(message) { throw new ValidationError(message); }
function check(condition, message) { if (!condition) fail(message); }

// Number syntax must be checked before JSON.parse erases the lexical form.
if (JSON.parse('0', (_key, _value, context) => context?.source) !== '0') {
  throw new Error('Conformance requires native JSON.parse source context (Node >=22.13)');
}
function parseWireJSON(raw) {
  try {
    return JSON.parse(raw, (_key, value, context) => {
      if (typeof value === 'number') {
        check(/^-?(?:0|[1-9][0-9]*)$/.test(context.source),
          'JSON number must use an integer token');
        check(Number.isSafeInteger(value), 'JSON integer exceeds the safe range');
      }
      return value;
    });
  } catch (error) {
    if (error instanceof SyntaxError) fail('invalid JSON syntax');
    throw error;
  }
}

const root = path.dirname(vectorPath);
const load = name => parseWireJSON(fs.readFileSync(path.join(root, name), 'utf8'));
const vectors = load('intent-solver-wire-cases-v1.json');
const inputSchema = load('intent-solver-input-schema-v1.json');
const outputSchema = load('intent-solver-output-schema-v1.json');
const proposalSchema = load('solver-proposal-schema-v1.json');
const envelopeSchema = load('intent-envelope-schema-v1.json');
const draftSchema = load('intent-draft-schema-v1.json');

const identifier = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const sha256 = /^sha256:[0-9a-f]{64}$/;
const mediaType = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/;
const domain = Buffer.from('NTH-DAO:IntentEnvelope:v1\0', 'utf8');
const base58Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function canonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    check(Number.isSafeInteger(value), 'numbers must be safe integers');
    return String(value);
  }
  if (typeof value === 'string') {
    check(!/[\ud800-\udfff]/u.test(value), 'unpaired surrogate');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  check(value && typeof value === 'object', 'unsupported JSON value');
  return `{${Object.keys(value).sort().map(
    key => `${JSON.stringify(key)}:${canonical(value[key])}`,
  ).join(',')}}`;
}
function digestText(value) {
  return `sha256:${crypto.createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
function digestObject(value) { return digestText(canonical(value)); }
function sortedUnique(values, allowEmpty = true) {
  check(Array.isArray(values) && (allowEmpty || values.length > 0), 'array required');
  check(values.join('\0') === [...new Set(values)].sort().join('\0'), 'sorted unique');
}
function text(value, maximum = 8192, multiline = true) {
  check(typeof value === 'string' && value.trim().length > 0, 'non-empty text');
  check(Buffer.byteLength(value, 'utf8') <= maximum, 'text byte limit');
  check(![...value].some(char => {
    const point = char.codePointAt(0);
    return (point < 32 && !(multiline && [9, 10, 13].includes(point))) || point === 127;
  }), 'forbidden control character');
}

function validateDefinition(schema, depth = 0) {
  const allowed = ['type', 'additionalProperties', 'properties', 'required', 'items',
    'enum', 'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems'];
  check(schema && typeof schema === 'object' && !Array.isArray(schema), 'schema object');
  check(depth <= 32 && Object.keys(schema).every(key => allowed.includes(key)), 'schema vocabulary');
  check(['object', 'array', 'string', 'boolean', 'integer'].includes(schema.type), 'schema type');
  if (schema.type === 'object') {
    check(schema.additionalProperties === false && schema.properties
      && Array.isArray(schema.required), 'closed object schema');
    check(new Set(schema.required).size === schema.required.length
      && schema.required.every(key => Object.hasOwn(schema.properties, key)), 'required fields');
    Object.values(schema.properties).forEach(child => validateDefinition(child, depth + 1));
  } else if (schema.type === 'array') {
    check(Object.hasOwn(schema, 'items'), 'array items');
    validateDefinition(schema.items, depth + 1);
  }
  if (schema.enum !== undefined) {
    check(Array.isArray(schema.enum) && schema.enum.length > 0, 'enum');
  }
}
function validate(value, schema, where) {
  const matches = schema.type === 'object'
    ? value !== null && typeof value === 'object' && !Array.isArray(value)
    : schema.type === 'array' ? Array.isArray(value)
      : schema.type === 'integer' ? Number.isSafeInteger(value)
        : typeof value === schema.type;
  check(matches, `${where} type`);
  if (schema.enum) check(schema.enum.some(item => canonical(item) === canonical(value)), `${where} enum`);
  if (schema.type === 'object') {
    check(Object.keys(value).every(key => Object.hasOwn(schema.properties, key)), `${where} unknown field`);
    check(schema.required.every(key => Object.hasOwn(value, key)), `${where} missing field`);
    Object.keys(value).forEach(key => validate(value[key], schema.properties[key], `${where}.${key}`));
  } else if (schema.type === 'array') {
    check(value.length >= (schema.minItems ?? 0) && value.length <= (schema.maxItems ?? Infinity), `${where} items`);
    value.forEach((item, index) => validate(item, schema.items, `${where}[${index}]`));
  } else if (schema.type === 'string') {
    const length = [...value].length;
    check(length >= (schema.minLength ?? 0) && length <= (schema.maxLength ?? Infinity), `${where} length`);
  } else if (schema.type === 'integer') {
    check(value >= (schema.minimum ?? -Infinity) && value <= (schema.maximum ?? Infinity), `${where} range`);
  }
}

function decodeBase58(value) {
  check(value.length > 0, 'base58 empty');
  let number = 0n;
  for (const char of value) {
    const index = base58Alphabet.indexOf(char);
    check(index >= 0, 'base58 alphabet');
    number = number * 58n + BigInt(index);
  }
  let hex = number === 0n ? '' : number.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const body = hex ? Buffer.from(hex, 'hex') : Buffer.alloc(0);
  let zeroes = 0;
  while (zeroes < value.length && value[zeroes] === '1') zeroes += 1;
  return Buffer.concat([Buffer.alloc(zeroes), body]);
}
function encodeBase58(value) {
  let zeroes = 0;
  while (zeroes < value.length && value[zeroes] === 0) zeroes += 1;
  let number = value.length ? BigInt(`0x${value.toString('hex') || '0'}`) : 0n;
  let encoded = '';
  while (number > 0n) {
    encoded = base58Alphabet[Number(number % 58n)] + encoded;
    number /= 58n;
  }
  return '1'.repeat(zeroes) + encoded;
}
function didPublicKey(did) {
  check(typeof did === 'string' && did.startsWith('did:key:z') && did.length <= 128, 'did:key');
  const raw = decodeBase58(did.slice('did:key:z'.length));
  check(raw.length === 34 && raw[0] === 0xed && raw[1] === 1, 'Ed25519 did:key');
  check(`did:key:z${encodeBase58(raw)}` === did, 'canonical did:key');
  const publicKey = raw.subarray(2);
  check(ed25519.utils.isValidPublicKey(publicKey, false), 'valid Ed25519 point');
  const point = ed25519.Point.fromBytes(publicKey, false);
  check(!point.isSmallOrder() && point.isTorsionFree(), 'prime-order Ed25519 point');
  return publicKey;
}

function verifyEnvelope(raw) {
  check(typeof raw === 'string' && Buffer.byteLength(raw, 'utf8') <= 262144, 'envelope size');
  let envelope;
  try { envelope = parseWireJSON(raw); } catch { fail('envelope JSON'); }
  validate(envelope, envelopeSchema, '$envelope');
  check(canonical(envelope) === raw, 'envelope canonical');
  const publicKey = didPublicKey(envelope.signer_did);
  didPublicKey(envelope.audience_did);
  check(identifier.test(envelope.scope_id), 'scope id');
  sortedUnique(envelope.solver_classes, false);
  check(envelope.solver_classes.every(item => identifier.test(item)), 'solver classes');
  check(envelope.expires_at_ms > envelope.issued_at_ms
    && envelope.expires_at_ms - envelope.issued_at_ms <= 86400000, 'envelope TTL');
  check(/^[0-9a-f]{128}$/.test(envelope.signature), 'signature encoding');
  const { signature, ...body } = envelope;
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    publicKey,
  ]);
  check(crypto.verify(
    null,
    Buffer.concat([domain, Buffer.from(canonical(body), 'utf8')]),
    { key: spki, format: 'der', type: 'spki' },
    Buffer.from(signature, 'hex'),
  ), 'envelope signature');
  const draft = parseWireJSON(envelope.draft_json);
  validate(draft, draftSchema, '$draft');
  check(canonical(draft) === envelope.draft_json, 'draft canonical');
  check(digestText(envelope.draft_json) === envelope.draft_digest, 'draft digest');
  return envelope;
}

function validateEvidence(item, where) {
  check(sha256.test(item.digest) && mediaType.test(item.media_type), `${where} digest/media`);
  text(item.source_ref, 2048, false);
  const expected = {
    'accepted-envelope': ['accepted-intent', 'signature-bound'],
    'invocation-materialized': [null, 'content-verified'],
    'solver-observed': [null, 'unverified'],
  }[item.provenance];
  check(expected && item.verification_status === expected[1], `${where} provenance status`);
  check(expected[0] === null || item.source_kind === expected[0], `${where} provenance source`);
  check(item.provenance === 'accepted-envelope' || item.source_kind !== 'accepted-intent', `${where} accepted binding`);
  if (item.provenance === 'accepted-envelope') check(sha256.test(item.source_ref), `${where} envelope ref`);
}
function validateEvidenceList(items, where, allowed = null) {
  items.forEach((item, index) => {
    validateEvidence(item, `${where}[${index}]`);
    if (allowed) check(allowed.has(item.provenance), `${where} provenance`);
  });
  sortedUnique(items.map(item => item.digest));
}
function evidenceDescriptor(item) {
  const { content_base64: _content, ...descriptor } = item;
  return descriptor;
}
function validateMaterializedEvidenceList(items, where) {
  let total = 0;
  items.forEach((item, index) => {
    const itemWhere = `${where}[${index}]`;
    validateEvidence(item, itemWhere);
    check(item.provenance === 'invocation-materialized', `${itemWhere} provenance`);
    check(typeof item.content_base64 === 'string', `${itemWhere} content`);
    const content = Buffer.from(item.content_base64, 'base64');
    check(content.toString('base64') === item.content_base64, `${itemWhere} canonical Base64`);
    check(content.length <= 131072, `${itemWhere} byte limit`);
    check(digestText(content) === item.digest, `${itemWhere} content digest`);
    total += content.length;
    check(total <= 262144, `${where} aggregate byte limit`);
  });
  sortedUnique(items.map(item => item.digest));
}

function validateInput(request) {
  validate(request, inputSchema, '$input');
  check(Buffer.byteLength(canonical(request), 'utf8') <= 1048576, 'input size');
  if (request.operation === 'probe') {
    check(Object.keys(request).length === 1, 'probe fields');
    return;
  }
  check(Object.keys(request).length === Object.keys(inputSchema.properties).length, 'propose fields');
  check(identifier.test(request.proposal_id) && identifier.test(request.solver_class), 'request identifiers');
  for (const field of ['intent_envelope_digest', 'acceptance_audit_digest', 'policy_snapshot_digest']) {
    check(sha256.test(request[field]), `${field} hash`);
  }
  const envelope = verifyEnvelope(request.intent_envelope_json);
  check(digestObject(envelope) === request.intent_envelope_digest, 'envelope digest binding');
  check(envelope.solver_classes.includes(request.solver_class), 'solver allowed');
  check(envelope.issued_at_ms <= request.proposed_at_ms
    && request.proposed_at_ms < request.expires_at_ms
    && request.expires_at_ms <= envelope.expires_at_ms
    && request.expires_at_ms - request.proposed_at_ms <= 3600000, 'proposal validity');
  validateMaterializedEvidenceList(request.evidence, '$input.evidence');
  check(request.evidence.every(item => item.observed_at_ms <= request.proposed_at_ms), 'future input evidence');
  check(!request.evidence.some(item => item.digest === envelope.draft_digest), 'draft evidence duplicate');
}

function validateProposal(proposal) {
  validate(proposal, proposalSchema, '$proposal');
  check(Buffer.byteLength(canonical(proposal), 'utf8') <= 262144, 'proposal size');
  for (const field of ['proposal_id', 'scope_id', 'solver_class', 'solver_plugin_id']) {
    check(identifier.test(proposal[field]), `${field} identifier`);
  }
  if (proposal.solver_did) didPublicKey(proposal.solver_did);
  for (const field of ['acceptance_audit_digest', 'draft_digest', 'intent_envelope_digest', 'policy_snapshot_digest']) {
    check(sha256.test(proposal[field]), `${field} hash`);
  }
  check(proposal.created_at_ms < proposal.expires_at_ms
    && proposal.expires_at_ms - proposal.created_at_ms <= 3600000, 'proposal TTL');
  text(proposal.summary);
  ['assumptions', 'constraints', 'proposed_actions', 'risks'].forEach(
    field => proposal[field].forEach(item => text(item)),
  );
  sortedUnique(proposal.requested_permissions);
  check(proposal.requested_permissions.every(item => identifier.test(item)), 'permission identifiers');
  validateEvidenceList(proposal.evidence, '$proposal.evidence');
  check(proposal.evidence.every(item => item.observed_at_ms <= proposal.created_at_ms), 'future proposal evidence');
  const evidence = new Map(proposal.evidence.map(item => [item.digest, item]));
  const accepted = proposal.evidence.filter(item => item.provenance === 'accepted-envelope');
  check(accepted.length === 1
    && accepted[0].digest === proposal.draft_digest
    && accepted[0].source_ref === proposal.intent_envelope_digest, 'accepted evidence binding');
  const statements = [];
  const referenced = new Set();
  for (const collection of ['facts', 'estimates']) {
    proposal[collection].forEach(item => {
      text(item.statement); statements.push(item.statement);
      if (collection === 'estimates') text(item.basis);
      sortedUnique(item.evidence_digests, false);
      item.evidence_digests.forEach(itemDigest => {
        check(sha256.test(itemDigest) && evidence.has(itemDigest), 'known evidence reference');
        referenced.add(itemDigest);
      });
    });
  }
  check(new Set(statements).size === statements.length, 'unique statements');
  check(referenced.has(proposal.draft_digest), 'draft evidence referenced');
  return proposal;
}

function parseProposal(raw) {
  check(typeof raw === 'string' && Buffer.byteLength(raw, 'utf8') <= 262144, 'proposal JSON size');
  let proposal;
  try { proposal = parseWireJSON(raw); } catch { fail('proposal JSON'); }
  validateProposal(proposal);
  check(canonical(proposal) === raw, 'proposal canonical');
  return proposal;
}

function validateOutput(response) {
  validate(response, outputSchema, '$output');
  sortedUnique(response.supported_solver_classes, false);
  check(response.supported_solver_classes.every(item => identifier.test(item)), 'supported classes');
  check(response.max_evidence <= 32 && response.max_proposal_bytes <= 262144, 'provider limits');
  check(response.ready && response.detail === '' && sha256.test(response.invocation_context_digest), 'ready/context');
  if (response.operation === 'probe') {
    check(!response.proposal_json && !response.proposal_sha256 && !response.status, 'probe state');
    return;
  }
  parseProposal(response.proposal_json);
  check(digestText(response.proposal_json) === response.proposal_sha256, 'proposal digest');
  check(response.status === 'proposal', 'proposal status');
}

function validateExchange(request, response) {
  check(request.operation === response.operation, 'operation binding');
  if (request.operation === 'probe') return;
  check(response.supported_solver_classes.includes(request.solver_class), 'requested solver class support');
  const proposal = parseProposal(response.proposal_json);
  const envelope = verifyEnvelope(request.intent_envelope_json);
  const bindings = {
    acceptance_audit_digest: request.acceptance_audit_digest,
    created_at_ms: request.proposed_at_ms,
    expires_at_ms: request.expires_at_ms,
    intent_envelope_digest: request.intent_envelope_digest,
    policy_snapshot_digest: request.policy_snapshot_digest,
    proposal_id: request.proposal_id,
    solver_class: request.solver_class,
  };
  Object.entries(bindings).forEach(([field, expected]) => check(proposal[field] === expected, `${field} input binding`));
  check(proposal.draft_digest === envelope.draft_digest && proposal.scope_id === envelope.scope_id, 'envelope fields');
  const draft = parseWireJSON(envelope.draft_json);
  check(proposal.requested_permissions.every(item => draft.requested_capabilities.includes(item)), 'permission expansion');
  const proposalEvidence = new Map(proposal.evidence.map(item => [item.digest, canonical(item)]));
  request.evidence.forEach(item => check(
    proposalEvidence.get(item.digest) === canonical(evidenceDescriptor(item)),
    'Host evidence preservation',
  ));
  const accepted = {
    digest: envelope.draft_digest,
    media_type: 'application/vnd.nth-dao.intent-draft+json',
    observed_at_ms: request.proposed_at_ms,
    provenance: 'accepted-envelope',
    source_kind: 'accepted-intent',
    source_ref: request.intent_envelope_digest,
    verification_status: 'signature-bound',
  };
  check(proposalEvidence.get(accepted.digest) === canonical(accepted), 'accepted evidence preservation');
}

function validateContext(response, context) {
  const fields = ['capability_id', 'format', 'idempotency_key', 'invocation_id',
    'mandate_digest', 'plugin_id', 'principal', 'resource_ids'];
  check(context && typeof context === 'object' && !Array.isArray(context)
    && Object.keys(context).sort().join('\0') === fields.sort().join('\0'), 'context fields');
  check(context.format === 'org.nth-dao.intent-solver-invocation-context.v1'
    && context.capability_id === 'org.nth-dao.intent.propose', 'context profile');
  ['capability_id', 'invocation_id', 'plugin_id'].forEach(field => check(identifier.test(context[field]), `${field} identifier`));
  text(context.principal, 512);
  if (context.mandate_digest) check(sha256.test(context.mandate_digest), 'context audit digest');
  if (context.idempotency_key) check(identifier.test(context.idempotency_key), 'context idempotency');
  sortedUnique(context.resource_ids);
  check(context.resource_ids.every(item => sha256.test(item)), 'context resources');
  check(digestObject(context) === response.invocation_context_digest, 'context digest binding');
  if (response.operation === 'propose') {
    check(parseProposal(response.proposal_json).solver_plugin_id === context.plugin_id, 'plugin context binding');
  }
}

function validateAuthority(request, authority) {
  check(authority && typeof authority === 'object', 'authority object');
  check(authority.capability_ids.includes('org.nth-dao.intent.propose'), 'authority capability');
  if (request.operation === 'probe') {
    check(!authority.mandate_digest && !authority.idempotency_key
      && authority.resource_ids.length === 0, 'probe business authority');
    return;
  }
  check(authority.mandate_digest === request.acceptance_audit_digest, 'acceptance audit authority');
  check(authority.idempotency_key === request.proposal_id, 'proposal idempotency authority');
  const expected = [request.intent_envelope_digest, request.policy_snapshot_digest,
    ...request.evidence.map(item => item.digest)].sort();
  check(canonical(authority.resource_ids) === canonical(expected), 'authority resources');
}

[inputSchema, outputSchema, proposalSchema, envelopeSchema, draftSchema].forEach(validateDefinition);

vectors.positive_inputs.forEach(validateInput);
vectors.positive_outputs.forEach(validateOutput);
vectors.positive_exchanges.forEach(item => {
  validateInput(item.request);
  validateAuthority(item.request, item.authority);
  validateOutput(item.response);
  validateExchange(item.request, item.response);
  validateContext(item.response, item.context);
});
for (const [collection, validator, field] of [
  ['negative_inputs', validateInput, 'input'],
  ['negative_outputs', validateOutput, 'output'],
]) {
  vectors[collection].forEach(item => {
    let rejected = false;
    try { validator(item[field]); } catch (error) {
      if (!(error instanceof ValidationError)) throw error;
      rejected = true;
    }
    check(rejected, `${collection} accepted: ${item.name}`);
  });
}
vectors.negative_exchanges.forEach(item => {
  validateInput(item.request); validateOutput(item.response);
  let rejected = false;
  try { validateExchange(item.request, item.response); } catch (error) {
    if (!(error instanceof ValidationError)) throw error;
    rejected = true;
  }
  check(rejected, `negative exchange accepted: ${item.name}`);
});
vectors.negative_context_bindings.forEach(item => {
  validateOutput(item.response);
  let rejected = false;
  try { validateContext(item.response, item.context); } catch (error) {
    if (!(error instanceof ValidationError)) throw error;
    rejected = true;
  }
  check(rejected, `negative context accepted: ${item.name}`);
});
vectors.negative_authorities.forEach(item => {
  validateInput(item.request);
  let rejected = false;
  try { validateAuthority(item.request, item.authority); } catch (error) {
    if (!(error instanceof ValidationError)) throw error;
    rejected = true;
  }
  check(rejected, `negative authority accepted: ${item.name}`);
});
for (const [collection, field, validator] of [
  ['raw_negative_inputs', 'input_json', raw => validateInput(parseWireJSON(raw))],
  ['raw_negative_outputs', 'output_json', raw => validateOutput(parseWireJSON(raw))],
  ['raw_negative_proposals', 'proposal_json', parseProposal],
]) {
  vectors[collection].forEach(item => {
    let rejected = false;
    try { validator(item[field]); } catch (error) {
      if (!(error instanceof ValidationError)) throw error;
      rejected = true;
    }
    check(rejected, `${collection} accepted: ${item.name}`);
  });
}

process.stdout.write(JSON.stringify({
  positive_inputs: vectors.positive_inputs.length,
  positive_outputs: vectors.positive_outputs.length,
  positive_exchanges: vectors.positive_exchanges.length,
  negative_inputs: vectors.negative_inputs.length,
  negative_outputs: vectors.negative_outputs.length,
  negative_exchanges: vectors.negative_exchanges.length,
  negative_contexts: vectors.negative_context_bindings.length,
  negative_authorities: vectors.negative_authorities.length,
  raw_negative_inputs: vectors.raw_negative_inputs.length,
  raw_negative_outputs: vectors.raw_negative_outputs.length,
  raw_negative_proposals: vectors.raw_negative_proposals.length,
}));

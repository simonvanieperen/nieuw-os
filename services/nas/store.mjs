import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { NasError, fail, requireId, requireRevision, requireKeys, decode64, CAPABILITY, NAMESPACE } from './errors.mjs';
import { MAX_ENVELOPE_BYTES, parseEnvelope } from './crypto.mjs';

const FORMAT = 'nieuw-os-n01-synthetic-v1';
const MAX_NAMESPACES = 16; // Includes durable tombstones: never garbage-collect authority silently.
const MAX_OBJECTS = 32;
const MAX_QUOTA = 2_000_000;
const MAX_STATE_BYTES = 48_000_000;
const MAX_NONCES = 8_192;
const BOOTSTRAP = Symbol('synthetic-store-bootstrap');
const token = () => randomBytes(32).toString('base64url');
const digest = (value) => createHash('sha256').update(value).digest('hex');
const tokenDigest = (value) => {
  if (typeof value !== 'string' || !CAPABILITY.test(value)) fail('DENIED');
  return digest(value);
};
const equalDigest = (a, b) => typeof b === 'string' && NAMESPACE.test(b) &&
  timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
const usedBytes = (ns) => Object.values(ns.objects).reduce((sum, record) => sum + record.size, 0);

// Validate the opened descriptor, not the path: a path check followed by a reopen
// lets a concurrent rename swap in a symlink or larger file between the two calls.
// O_NOFOLLOW rejects a symlink at open; O_NONBLOCK keeps a FIFO from blocking open.
// ELOOP is a symlink and ENXIO a socket or unbacked device: both are not store files.
const READ_FLAGS = fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
function readSmall(file, maximum) {
  let fd;
  try { fd = fs.openSync(file, READ_FLAGS); }
  catch (error) { if (error.code === 'ELOOP' || error.code === 'ENXIO') fail('INVALID_STORE'); throw error; }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > maximum) fail('INVALID_STORE');
    const bytes = Buffer.alloc(stat.size + 1);
    // One extra byte detects a file that changed size after fstat.
    if (fs.readSync(fd, bytes, 0, bytes.length, 0) !== stat.size) fail('INVALID_STORE');
    return bytes.subarray(0, stat.size);
  } finally { fs.closeSync(fd); }
}
function validateState(state, marker) {
  requireKeys(state, ['format', 'storeId', 'peerIdentity', 'adminDigest', 'namespaces']);
  if (state.format !== FORMAT || state.storeId !== marker.storeId || !NAMESPACE.test(state.storeId) ||
      !NAMESPACE.test(state.peerIdentity) || !NAMESPACE.test(state.adminDigest) ||
      !state.namespaces || typeof state.namespaces !== 'object' || Array.isArray(state.namespaces) ||
      Object.keys(state.namespaces).length > MAX_NAMESPACES) fail('INVALID_STORE');
  for (const [namespace, ns] of Object.entries(state.namespaces)) {
    requireId(namespace, true);
    requireKeys(ns, ['status', 'epoch', 'quotaBytes', 'invite', 'userDigest', 'objects', 'revisions', 'nonces']);
    if (!['offered', 'active', 'revoked', 'evicted'].includes(ns.status) ||
        !Number.isSafeInteger(ns.epoch) || ns.epoch < 1 ||
        !Number.isSafeInteger(ns.quotaBytes) || ns.quotaBytes < 256 || ns.quotaBytes > MAX_QUOTA ||
        !ns.objects || typeof ns.objects !== 'object' || Array.isArray(ns.objects) ||
        !ns.revisions || typeof ns.revisions !== 'object' || Array.isArray(ns.revisions) ||
        Object.keys(ns.revisions).length > MAX_OBJECTS || Object.keys(ns.objects).length > MAX_OBJECTS ||
        !Array.isArray(ns.nonces) || ns.nonces.length > MAX_NONCES ||
        new Set(ns.nonces).size !== ns.nonces.length || ns.nonces.some(n => !/^[a-f0-9]{24}$/.test(n))) fail('INVALID_STORE');
    if (ns.status === 'active') {
      if (!NAMESPACE.test(ns.userDigest) || ns.invite !== null) fail('INVALID_STORE');
    } else if (ns.userDigest !== null) fail('INVALID_STORE');
    if (ns.status === 'offered') {
      requireKeys(ns.invite, ['digest', 'expiresAt']);
      if (!NAMESPACE.test(ns.invite.digest) || !Number.isSafeInteger(ns.invite.expiresAt)) fail('INVALID_STORE');
    } else if (ns.invite !== null) fail('INVALID_STORE');
    if (ns.status === 'evicted' && (Object.keys(ns.objects).length || Object.keys(ns.revisions).length || ns.nonces.length)) fail('INVALID_STORE');
    for (const [objectId, revision] of Object.entries(ns.revisions)) { requireId(objectId); requireRevision(revision); }
    for (const [objectId, record] of Object.entries(ns.objects)) {
      requireId(objectId); requireKeys(record, ['size', 'bytes']);
      const bytes = decode64(record.bytes, MAX_ENVELOPE_BYTES);
      const envelope = parseEnvelope(bytes);
      if (record.size !== bytes.length || envelope.namespace !== namespace || envelope.objectId !== objectId ||
          envelope.revision !== ns.revisions[objectId] || !ns.nonces.includes(Buffer.from(envelope.nonce, 'base64').toString('hex'))) fail('INVALID_STORE');
    }
    if (usedBytes(ns) > ns.quotaBytes) fail('INVALID_STORE');
  }
  return state;
}

export class NasStore {
  #directory; #state; #clock; #closed = false; #poisoned = false; #lockToken;
  #sessions = new Map(); #uploads = new Map();
  constructor(bootstrap, directory, state, clock) {
    if (bootstrap !== BOOTSTRAP) fail('USE_SYNTHETIC_FACTORY');
    this.#directory = directory; this.#state = state; this.#clock = clock;
    this.#acquireLock();
  }
  static createSynthetic({ clock = Date.now } = {}) {
    if (typeof clock !== 'function') fail('INVALID_CLOCK');
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nieuw-os-n01-'));
    fs.chmodSync(directory, 0o700);
    const adminCapability = token();
    const state = { format: FORMAT, storeId: randomBytes(32).toString('hex'),
      peerIdentity: randomBytes(32).toString('hex'), adminDigest: digest(adminCapability), namespaces: {} };
    fs.writeFileSync(path.join(directory, 'synthetic.json'), JSON.stringify({ format: FORMAT, storeId: state.storeId }), { mode: 0o600, flag: 'wx' });
    const store = new NasStore(BOOTSTRAP, directory, state, clock);
    try { store.#persist(state); } catch (error) { store.close(); fs.rmSync(directory, { recursive: true }); throw error; }
    return { store, adminCapability };
  }
  static openSynthetic({ directory, clock = Date.now }) {
    if (typeof directory !== 'string' || typeof clock !== 'function') fail('INVALID_STORE');
    const absolute = path.resolve(directory);
    const stat = fs.lstatSync(absolute);
    if (!stat.isDirectory() || stat.isSymbolicLink() || !path.basename(absolute).startsWith('nieuw-os-n01-')) fail('INVALID_STORE');
    const marker = JSON.parse(readSmall(path.join(absolute, 'synthetic.json'), 512));
    requireKeys(marker, ['format', 'storeId']);
    if (marker.format !== FORMAT || !NAMESPACE.test(marker.storeId)) fail('INVALID_STORE');
    // Acquire the exclusive lock before reading the authoritative snapshot.
    const store = new NasStore(BOOTSTRAP, absolute, null, clock);
    try {
      store.#state = validateState(JSON.parse(readSmall(path.join(absolute, 'state.json'), MAX_STATE_BYTES)), marker);
      store.#cleanupAbandonedSnapshots();
      return store;
    } catch (error) { store.close(); throw new NasError('INVALID_STORE'); }
  }
  get directory() { return this.#directory; }
  get peerIdentity() { this.#ready(); return this.#state.peerIdentity; }
  #acquireLock() {
    const file = path.join(this.#directory, 'writer.lock');
    this.#lockToken = token();
    const claim = () => fs.writeFileSync(file, JSON.stringify({ pid: process.pid, token: this.#lockToken }), { flag: 'wx', mode: 0o600 });
    try { claim(); return; } catch (error) { if (error.code !== 'EEXIST') throw error; }
    // Serialize stale-lock recovery. A mere PID/token check followed by unlink is racy.
    const recovery = path.join(this.#directory, 'recovery.lock');
    let recoveryFd;
    try { recoveryFd = fs.openSync(recovery, 'wx', 0o600); } catch { fail('STORE_BUSY'); }
    try {
      let lock;
      try { lock = JSON.parse(readSmall(file, 512)); }
      catch (error) { if (error.code !== 'ENOENT') fail('STORE_BUSY'); }
      if (lock) {
        if (!Number.isSafeInteger(lock.pid) || lock.pid < 1) fail('STORE_BUSY');
        try { process.kill(lock.pid, 0); fail('STORE_BUSY'); }
        catch (probe) { if (probe.code !== 'ESRCH') fail('STORE_BUSY'); }
        fs.unlinkSync(file); // Only a dead local PID, while holding recovery.lock.
      }
      try { claim(); } catch { fail('STORE_BUSY'); }
    } finally {
      fs.closeSync(recoveryFd); fs.unlinkSync(recovery);
    }
    // A process dying while holding recovery.lock requires offline operator recovery.
    // That second lock is deliberately never automatically stolen.
  }
  #cleanupAbandonedSnapshots() {
    let removed = false;
    for (const name of fs.readdirSync(this.#directory)) {
      if (!/^\.state-[a-f0-9]{32}\.tmp$/.test(name)) continue;
      const file = path.join(this.#directory, name); const stat = fs.lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink()) fail('SNAPSHOT_CLEANUP_FAILED');
      fs.unlinkSync(file); removed = true;
    }
    if (removed) {
      const fd = fs.openSync(this.#directory, 'r');
      try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    }
  }
  #ready() {
    if (this.#closed) fail('STORE_CLOSED');
    if (this.#poisoned) fail('REOPEN_REQUIRED');
  }
  #persist(state) {
    const bytes = Buffer.from(JSON.stringify(state));
    if (bytes.length > MAX_STATE_BYTES) fail('STORE_FULL');
    const temporary = path.join(this.#directory, `.state-${randomBytes(16).toString('hex')}.tmp`);
    let fd;
    try {
      this.#cleanupAbandonedSnapshots();
      fd = fs.openSync(temporary, 'wx', 0o600);
      fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
      fs.renameSync(temporary, path.join(this.#directory, 'state.json'));
      const dirfd = fs.openSync(this.#directory, 'r');
      try { fs.fsyncSync(dirfd); } finally { fs.closeSync(dirfd); }
    } catch {
      this.#poisoned = true; // Never continue from an ambiguous in-memory/disk split.
      if (fd !== undefined) fs.closeSync(fd);
      try { fs.unlinkSync(temporary); } catch { /* Ciphertext-only abandoned temp, if any. */ }
      fail('PERSISTENCE_FAILURE');
    }
  }
  #change(change) {
    this.#ready();
    const next = structuredClone(this.#state);
    const result = change(next);
    this.#persist(next); this.#state = next;
    return result;
  }
  #admin(capability) {
    this.#ready();
    if (!equalDigest(tokenDigest(capability), this.#state.adminDigest)) fail('DENIED');
  }
  #namespace(namespace) {
    requireId(namespace, true);
    const ns = this.#state.namespaces[namespace];
    if (!ns) fail('NAMESPACE_NOT_FOUND');
    return ns;
  }
  #session(capability) {
    this.#ready();
    const hash = tokenDigest(capability);
    const session = this.#sessions.get(hash);
    const ns = session && this.#state.namespaces[session.namespace];
    if (!session || ns?.status !== 'active' || ns.epoch !== session.epoch) fail('INVALID_SESSION');
    return { ...session, hash, ns };
  }
  #dropNamespaceHandles(namespace) {
    for (const [id, session] of this.#sessions) if (session.namespace === namespace) this.#sessions.delete(id);
    for (const [id, upload] of this.#uploads) if (upload.namespace === namespace) this.#uploads.delete(id);
  }
  createInvitation(adminCapability, { quotaBytes = 1_000_000, lifetimeMs = 300_000 } = {}) {
    this.#admin(adminCapability);
    if (!Number.isSafeInteger(quotaBytes) || quotaBytes < 256 || quotaBytes > MAX_QUOTA ||
        !Number.isSafeInteger(lifetimeMs) || lifetimeMs < 1 || lifetimeMs > 86_400_000) fail('INVALID_LIMIT');
    if (Object.keys(this.#state.namespaces).length >= MAX_NAMESPACES) fail('STORE_FULL');
    let namespace;
    do { namespace = randomBytes(32).toString('hex'); } while (this.#state.namespaces[namespace]);
    const invitation = token(); const expiresAt = this.#clock() + lifetimeMs;
    if (!Number.isSafeInteger(expiresAt) || expiresAt < 1) fail('INVALID_CLOCK');
    this.#change(state => { state.namespaces[namespace] = { status: 'offered', epoch: 1, quotaBytes,
      invite: { digest: digest(invitation), expiresAt }, userDigest: null, objects: {}, revisions: {}, nonces: [] }; });
    return { namespace, invitation, expiresAt, peerIdentity: this.#state.peerIdentity };
  }
  acceptInvitation({ namespace, invitation, confirmedPeerIdentity }) {
    this.#ready();
    const ns = this.#namespace(namespace);
    if (confirmedPeerIdentity !== this.#state.peerIdentity || ns.status !== 'offered' ||
        this.#clock() >= ns.invite.expiresAt || !equalDigest(tokenDigest(invitation), ns.invite.digest)) fail('PAIRING_DENIED');
    const accessCapability = token();
    this.#change(state => { const target = state.namespaces[namespace]; target.status = 'active';
      target.invite = null; target.userDigest = digest(accessCapability); });
    return { namespace, accessCapability, peerIdentity: this.#state.peerIdentity };
  }
  openSession({ namespace, accessCapability }) {
    this.#ready(); const ns = this.#namespace(namespace);
    if (ns.status !== 'active' || !equalDigest(tokenDigest(accessCapability), ns.userDigest)) fail('DENIED');
    if (this.#sessions.size >= 128 || [...this.#sessions.values()].filter(s => s.namespace === namespace).length >= 16) fail('SESSION_LIMIT');
    const session = token();
    this.#sessions.set(digest(session), { namespace, epoch: ns.epoch });
    return session;
  }
  closeSession(session) {
    const auth = this.#session(session); this.#sessions.delete(auth.hash);
    for (const [id, upload] of this.#uploads) if (upload.sessionHash === auth.hash) this.#uploads.delete(id);
  }
  stageUpload(session, bytes) {
    const auth = this.#session(session);
    // Snapshot caller bytes before parsing, accounting or retaining them.
    if (!Buffer.isBuffer(bytes) || bytes.length > MAX_ENVELOPE_BYTES) fail('INVALID_ENVELOPE');
    const copy = Buffer.from(bytes); const envelope = parseEnvelope(copy);
    if (envelope.namespace !== auth.namespace) fail('TENANT_MISMATCH');
    if (envelope.revision !== (auth.ns.revisions[envelope.objectId] || 0) + 1) fail('REVISION_CONFLICT');
    if (!(envelope.objectId in auth.ns.revisions) && Object.keys(auth.ns.revisions).length >= MAX_OBJECTS) fail('OBJECT_LIMIT');
    const nonce = Buffer.from(envelope.nonce, 'base64').toString('hex');
    const uploads = [...this.#uploads.values()].filter(u => u.namespace === auth.namespace);
    if (auth.ns.nonces.length + uploads.length >= MAX_NONCES) fail('KEY_ROTATION_REQUIRED');
    if (auth.ns.nonces.includes(nonce) || uploads.some(u => u.nonce === nonce)) fail('NONCE_REUSE');
    if (uploads.length >= 8) fail('UPLOAD_LIMIT');
    if (usedBytes(auth.ns) + uploads.reduce((sum, u) => sum + u.bytes.length, 0) + copy.length > auth.ns.quotaBytes) fail('QUOTA_EXCEEDED');
    const upload = token();
    this.#uploads.set(digest(upload), { namespace: auth.namespace, epoch: auth.epoch,
      sessionHash: auth.hash, bytes: copy, envelope, nonce });
    return upload;
  }
  commitUpload(session, uploadToken) {
    const auth = this.#session(session); const uploadHash = tokenDigest(uploadToken);
    const upload = this.#uploads.get(uploadHash);
    if (!upload || upload.namespace !== auth.namespace || upload.epoch !== auth.epoch || upload.sessionHash !== auth.hash) fail('INVALID_UPLOAD');
    const { objectId, revision } = upload.envelope;
    if (revision !== (auth.ns.revisions[objectId] || 0) + 1) {
      this.#uploads.delete(uploadHash); fail('REVISION_CONFLICT');
    }
    if (auth.ns.nonces.includes(upload.nonce)) { this.#uploads.delete(uploadHash); fail('NONCE_REUSE'); }
    if (auth.ns.nonces.length >= MAX_NONCES) fail('KEY_ROTATION_REQUIRED');
    if (!(objectId in auth.ns.revisions) && Object.keys(auth.ns.revisions).length >= MAX_OBJECTS) fail('OBJECT_LIMIT');
    const size = usedBytes(auth.ns) - (auth.ns.objects[objectId]?.size || 0) + upload.bytes.length;
    if (size > auth.ns.quotaBytes) fail('QUOTA_EXCEEDED');
    this.#change(state => { const ns = state.namespaces[auth.namespace];
      ns.objects[objectId] = { size: upload.bytes.length, bytes: upload.bytes.toString('base64') };
      ns.revisions[objectId] = revision; ns.nonces.push(upload.nonce); });
    this.#uploads.delete(uploadHash);
    return { objectId, revision, storedBytes: upload.bytes.length };
  }
  cancelUpload(session, uploadToken) {
    const auth = this.#session(session); const hash = tokenDigest(uploadToken); const upload = this.#uploads.get(hash);
    if (!upload || upload.sessionHash !== auth.hash || upload.epoch !== auth.epoch) fail('INVALID_UPLOAD');
    this.#uploads.delete(hash);
  }
  readObject(session, objectId) {
    const auth = this.#session(session); requireId(objectId);
    const record = auth.ns.objects[objectId];
    if (!record) fail('OBJECT_NOT_FOUND');
    return Buffer.from(record.bytes, 'base64');
  }
  listObjects(session) {
    const auth = this.#session(session);
    return Object.entries(auth.ns.objects).map(([objectId, record]) => ({ objectId, revision: auth.ns.revisions[objectId], storedBytes: record.size }));
  }
  inspectUsage(adminCapability) {
    this.#admin(adminCapability);
    return Object.entries(this.#state.namespaces).map(([namespace, ns]) => ({ namespace, status: ns.status,
      epoch: ns.epoch, storedBytes: usedBytes(ns), quotaBytes: ns.quotaBytes, objectCount: Object.keys(ns.objects).length }));
  }
  revokeNamespace(adminCapability, namespace) {
    this.#admin(adminCapability); const ns = this.#namespace(namespace);
    if (ns.status === 'revoked' || ns.status === 'evicted') return { status: ns.status, epoch: ns.epoch };
    this.#change(state => { const target = state.namespaces[namespace]; target.status = 'revoked';
      target.epoch++; target.userDigest = null; target.invite = null; });
    this.#dropNamespaceHandles(namespace);
    return { status: 'revoked', epoch: this.#state.namespaces[namespace].epoch };
  }
  evictNamespace(adminCapability, namespace) {
    this.#admin(adminCapability); const ns = this.#namespace(namespace);
    if (ns.status === 'evicted') return { status: 'evicted', epoch: ns.epoch };
    this.#change(state => { const target = state.namespaces[namespace]; target.status = 'evicted'; target.epoch++;
      target.userDigest = null; target.invite = null; target.objects = {}; target.revisions = {}; target.nonces = []; });
    this.#dropNamespaceHandles(namespace);
    return { status: 'evicted', epoch: this.#state.namespaces[namespace].epoch };
  }
  deleteObject(adminCapability, namespace, objectId) {
    this.#admin(adminCapability); const ns = this.#namespace(namespace); requireId(objectId);
    if (!ns.objects[objectId]) return { deleted: false };
    this.#change(state => { const target = state.namespaces[namespace]; delete target.objects[objectId]; target.epoch++; });
    this.#dropNamespaceHandles(namespace);
    return { deleted: true }; // Revisions/nonces remain; user must explicitly open a new session.
  }
  close() {
    if (this.#closed) return;
    this.#closed = true; this.#sessions.clear(); this.#uploads.clear();
    const file = path.join(this.#directory, 'writer.lock');
    try { const lock = JSON.parse(readSmall(file, 512)); if (lock.token === this.#lockToken) fs.unlinkSync(file); }
    catch { /* Never delete an unrecognised lock. */ }
  }
}

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { execFileSync, fork } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { NasStore } from '../store.mjs';
import { createDocumentCipher, MAX_ENVELOPE_BYTES } from '../crypto.mjs';

const objectId = '1'.repeat(32);
const document = { name: 'SYNTHETIC-SECRET-NAME.txt', content: 'SYNTHETIC-SECRET-CONTENT' };
function fixture(t, options = {}) {
  const created = NasStore.createSynthetic(options);
  const holder = { ...created };
  t.after(() => { holder.store.close(); fs.rmSync(holder.store.directory, { recursive: true, force: true }); });
  return holder;
}
function pair(store, adminCapability, limits = {}) {
  const offer = store.createInvitation(adminCapability, limits);
  const paired = store.acceptInvitation({ ...offer, confirmedPeerIdentity: offer.peerIdentity });
  return { ...paired, offer, session: store.openSession(paired), cipher: createDocumentCipher(offer.namespace) };
}
function upload(store, user, id = objectId, revision = 1, input = document) {
  const bytes = user.cipher.encrypt({ objectId: id, revision, ...input });
  const staged = store.stageUpload(user.session, bytes);
  store.commitUpload(user.session, staged);
  return bytes;
}
function restart(holder) {
  const directory = holder.store.directory; holder.store.close();
  holder.store = NasStore.openSynthetic({ directory });
}

test('actual disk storage contains ciphertext and metadata, no document name/content or secrets', (t) => {
  const { store, adminCapability } = fixture(t); const user = pair(store, adminCapability);
  const bytes = upload(store, user);
  assert.deepEqual(user.cipher.decrypt({ objectId, revision: 1 }, store.readObject(user.session, objectId)), document);
  const disk = fs.readFileSync(path.join(store.directory, 'state.json'));
  for (const secret of [document.name, document.content, user.cipher.exportRecoveryKey().toString('base64'),
    adminCapability, user.accessCapability, user.session, user.offer.invitation]) assert.equal(disk.includes(Buffer.from(secret)), false);
  assert.equal(disk.includes(Buffer.from(bytes.toString('base64'))), true);
  assert.equal(fs.statSync(store.directory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(path.join(store.directory, 'state.json')).mode & 0o777, 0o600);
  assert.deepEqual(store.listObjects(user.session), [{ objectId, revision: 1, storedBytes: bytes.length }]);
});

test('single-use invite requires explicit identity confirmation and survives restart as consumed', (t) => {
  const holder = fixture(t); const { adminCapability } = holder; const offer = holder.store.createInvitation(adminCapability);
  assert.throws(() => holder.store.acceptInvitation({ ...offer, confirmedPeerIdentity: 'f'.repeat(64) }), { code: 'PAIRING_DENIED' });
  const request = { ...offer, confirmedPeerIdentity: offer.peerIdentity };
  holder.store.acceptInvitation(request);
  assert.throws(() => holder.store.acceptInvitation(request), { code: 'PAIRING_DENIED' });
  restart(holder);
  assert.throws(() => holder.store.acceptInvitation(request), { code: 'PAIRING_DENIED' });
});

test('expired invites cannot be accepted at the exact expiration boundary', (t) => {
  let now = 1_000; const { store, adminCapability } = fixture(t, { clock: () => now });
  const offer = store.createInvitation(adminCapability, { lifetimeMs: 10 }); now = 1_010;
  assert.throws(() => store.acceptInvitation({ ...offer, confirmedPeerIdentity: offer.peerIdentity }), { code: 'PAIRING_DENIED' });
});

test('admin capability cannot read as a user; user capability cannot administer any tenant', (t) => {
  const { store, adminCapability } = fixture(t); const user = pair(store, adminCapability); upload(store, user);
  assert.throws(() => store.openSession({ namespace: user.namespace, accessCapability: adminCapability }), { code: 'DENIED' });
  assert.throws(() => store.readObject(adminCapability, objectId), { code: 'INVALID_SESSION' });
  for (const action of [() => store.createInvitation(user.accessCapability), () => store.inspectUsage(user.accessCapability),
    () => store.evictNamespace(user.session, user.namespace), () => store.deleteObject(user.accessCapability, user.namespace, objectId)]) {
    assert.throws(action, { code: 'DENIED' });
  }
});

test('two tenants with identical object IDs stay isolated, including staged bytes and access credentials', (t) => {
  const { store, adminCapability } = fixture(t); const a = pair(store, adminCapability); const b = pair(store, adminCapability);
  const aBytes = upload(store, a); upload(store, b, objectId, 1, { name: 'B', content: 'Tenant B' });
  assert.equal(b.cipher.decrypt({ objectId, revision: 1 }, store.readObject(b.session, objectId)).content, 'Tenant B');
  assert.throws(() => a.cipher.decrypt({ objectId, revision: 1 }, store.readObject(b.session, objectId)), { code: 'AUTHENTICATION_FAILED' });
  assert.throws(() => store.openSession({ namespace: a.namespace, accessCapability: b.accessCapability }), { code: 'DENIED' });
  assert.throws(() => store.stageUpload(b.session, aBytes), { code: 'TENANT_MISMATCH' });
  const bStage = store.stageUpload(b.session, b.cipher.encrypt({ objectId, revision: 2, name: 'B2', content: 'B2' }));
  assert.throws(() => store.commitUpload(a.session, bStage), { code: 'INVALID_UPLOAD' });
});

test('quota counts staged uploads, cancellation releases reservations, oversized input is bounded', (t) => {
  const { store, adminCapability } = fixture(t); const user = pair(store, adminCapability, { quotaBytes: 512 });
  const bytes = user.cipher.encrypt({ objectId, revision: 1, ...document });
  const staged = store.stageUpload(user.session, bytes);
  const next = user.cipher.encrypt({ objectId: '2'.repeat(32), revision: 1, ...document });
  assert.throws(() => store.stageUpload(user.session, next), { code: 'QUOTA_EXCEEDED' });
  store.cancelUpload(user.session, staged);
  store.commitUpload(user.session, store.stageUpload(user.session, next));
  assert.equal(store.listObjects(user.session).length, 1);
  assert.throws(() => store.stageUpload(user.session, Buffer.alloc(MAX_ENVELOPE_BYTES + 1)), { code: 'INVALID_ENVELOPE' });
});

test('caller cannot change an in-flight upload by mutating its original Buffer', (t) => {
  const { store, adminCapability } = fixture(t); const user = pair(store, adminCapability);
  const bytes = user.cipher.encrypt({ objectId, revision: 1, ...document });
  const staged = store.stageUpload(user.session, bytes); bytes.fill(0);
  store.commitUpload(user.session, staged);
  assert.deepEqual(user.cipher.decrypt({ objectId, revision: 1 }, store.readObject(user.session, objectId)), document);
  assert.throws(() => store.commitUpload(user.session, staged), { code: 'INVALID_UPLOAD' });
});

test('concurrent writes cannot silently replace the same revision', (t) => {
  const { store, adminCapability } = fixture(t); const user = pair(store, adminCapability);
  const first = store.stageUpload(user.session, user.cipher.encrypt({ objectId, revision: 1, name: 'first', content: 'first' }));
  const second = store.stageUpload(user.session, user.cipher.encrypt({ objectId, revision: 1, name: 'second', content: 'second' }));
  store.commitUpload(user.session, first);
  assert.throws(() => store.commitUpload(user.session, second), { code: 'REVISION_CONFLICT' });
  assert.throws(() => store.commitUpload(user.session, second), { code: 'INVALID_UPLOAD' });
  assert.equal(user.cipher.decrypt({ objectId, revision: 1 }, store.readObject(user.session, objectId)).content, 'first');
});

test('revoke invalidates access, old sessions and in-flight uploads without the encryption key', (t) => {
  const holder = fixture(t); const { adminCapability } = holder; const user = pair(holder.store, adminCapability);
  upload(holder.store, user);
  const pending = holder.store.stageUpload(user.session, user.cipher.encrypt({ objectId, revision: 2, ...document }));
  holder.store.revokeNamespace(adminCapability, user.namespace);
  assert.throws(() => holder.store.commitUpload(user.session, pending), { code: 'INVALID_SESSION' });
  assert.throws(() => holder.store.readObject(user.session, objectId), { code: 'INVALID_SESSION' });
  assert.throws(() => holder.store.openSession(user), { code: 'DENIED' });
  restart(holder);
  assert.throws(() => holder.store.openSession(user), { code: 'DENIED' });
  assert.equal(holder.store.inspectUsage(adminCapability)[0].status, 'revoked');
  assert.equal(holder.store.inspectUsage(adminCapability)[0].objectCount, 1);
});

test('admin eviction deletes its stored copies, survives restart and prevents namespace resurrection', (t) => {
  const holder = fixture(t); const { adminCapability } = holder; const user = pair(holder.store, adminCapability);
  const bytes = upload(holder.store, user);
  const pending = holder.store.stageUpload(user.session, user.cipher.encrypt({ objectId, revision: 2, ...document }));
  holder.store.evictNamespace(adminCapability, user.namespace);
  assert.throws(() => holder.store.commitUpload(user.session, pending), { code: 'INVALID_SESSION' });
  const persisted = fs.readFileSync(path.join(holder.store.directory, 'state.json'));
  assert.equal(persisted.includes(Buffer.from(bytes.toString('base64'))), false);
  restart(holder);
  assert.throws(() => holder.store.openSession(user), { code: 'DENIED' });
  assert.throws(() => holder.store.acceptInvitation({ ...user.offer, confirmedPeerIdentity: user.offer.peerIdentity }), { code: 'PAIRING_DENIED' });
  assert.deepEqual(holder.store.inspectUsage(adminCapability).map(s => [s.status, s.storedBytes]), [['evicted', 0]]);
  const replacement = pair(holder.store, adminCapability);
  assert.notEqual(replacement.namespace, user.namespace);
  assert.throws(() => holder.store.stageUpload(replacement.session, bytes), { code: 'TENANT_MISMATCH' });
});

test('administrator deletes one object without user key/signature and invalidates pending replacement', (t) => {
  const { store, adminCapability } = fixture(t); const user = pair(store, adminCapability); const other = pair(store, adminCapability);
  upload(store, user); upload(store, other);
  const pending = store.stageUpload(user.session, user.cipher.encrypt({ objectId, revision: 2, ...document }));
  assert.deepEqual(store.deleteObject(adminCapability, user.namespace, objectId), { deleted: true });
  assert.throws(() => store.commitUpload(user.session, pending), { code: 'INVALID_SESSION' });
  user.session = store.openSession(user);
  assert.throws(() => store.readObject(user.session, objectId), { code: 'OBJECT_NOT_FOUND' });
  assert.equal(store.listObjects(other.session).length, 1);
  assert.throws(() => upload(store, user, objectId, 1), { code: 'REVISION_CONFLICT' });
  // A fresh user session may deliberately upload the next revision; eviction denies all future uploads.
  upload(store, user, objectId, 2);
});

test('durable nonce history rejects reuse even after administrator deletes the object', (t) => {
  const holder = fixture(t); const { adminCapability } = holder; const user = pair(holder.store, adminCapability);
  const bytes = upload(holder.store, user); holder.store.deleteObject(adminCapability, user.namespace, objectId);
  restart(holder); user.session = holder.store.openSession(user);
  const envelope = JSON.parse(bytes); envelope.revision = 2;
  assert.throws(() => holder.store.stageUpload(user.session, Buffer.from(JSON.stringify(envelope))), { code: 'NONCE_REUSE' });
});

test('clean server restart keeps ciphertext and quota but drops all old sessions and staged uploads', (t) => {
  const holder = fixture(t); const user = pair(holder.store, holder.adminCapability);
  const bytes = upload(holder.store, user);
  const pending = holder.store.stageUpload(user.session, user.cipher.encrypt({ objectId, revision: 2, ...document }));
  const oldSession = user.session; restart(holder);
  assert.throws(() => holder.store.readObject(oldSession, objectId), { code: 'INVALID_SESSION' });
  user.session = holder.store.openSession(user);
  assert.deepEqual(holder.store.readObject(user.session, objectId), bytes);
  assert.throws(() => holder.store.commitUpload(user.session, pending), { code: 'INVALID_UPLOAD' });
  assert.equal(holder.store.inspectUsage(holder.adminCapability)[0].storedBytes, bytes.length);
});

test('only one live store writer may open a synthetic directory', (t) => {
  const { store } = fixture(t);
  assert.throws(() => NasStore.openSynthetic({ directory: store.directory }), { code: 'STORE_BUSY' });
  assert.throws(() => new NasStore(store.directory, {}), { code: 'USE_SYNTHETIC_FACTORY' });
});

test('corrupted snapshot fails closed and is never replaced by an empty authority state', (t) => {
  const holder = fixture(t); const directory = holder.store.directory; holder.store.close();
  fs.writeFileSync(path.join(directory, 'state.json'), '{broken');
  assert.throws(() => NasStore.openSynthetic({ directory }), { code: 'INVALID_STORE' });
  assert.equal(fs.readFileSync(path.join(directory, 'state.json'), 'utf8'), '{broken');
});

test('symlinked snapshots are rejected without touching the target', (t) => {
  const holder = fixture(t); const directory = holder.store.directory; holder.store.close();
  const state = path.join(directory, 'state.json'); const target = path.join(directory, 'untouched.txt');
  fs.writeFileSync(target, 'synthetic sentinel'); fs.unlinkSync(state); fs.symlinkSync(target, state);
  assert.throws(() => NasStore.openSynthetic({ directory }), { code: 'INVALID_STORE' });
  assert.equal(fs.readFileSync(target, 'utf8'), 'synthetic sentinel');
});

test('a symlinked store marker is rejected at open', (t) => {
  const holder = fixture(t); const directory = holder.store.directory; holder.store.close();
  const marker = path.join(directory, 'synthetic.json'); const copy = path.join(directory, 'marker-copy.json');
  fs.renameSync(marker, copy); fs.symlinkSync(copy, marker);
  assert.throws(() => NasStore.openSynthetic({ directory }), { code: 'INVALID_STORE' });
});

test('a FIFO in place of the snapshot is rejected without blocking', (t) => {
  const holder = fixture(t); const directory = holder.store.directory; holder.store.close();
  const state = path.join(directory, 'state.json'); fs.unlinkSync(state);
  try { execFileSync('mkfifo', [state]); } catch { t.skip('mkfifo unavailable'); return; }
  assert.throws(() => NasStore.openSynthetic({ directory }), { code: 'INVALID_STORE' });
});

test('a socket in place of the store marker is rejected as an invalid store', async (t) => {
  const holder = fixture(t); const directory = holder.store.directory; holder.store.close();
  const marker = path.join(directory, 'synthetic.json'); fs.unlinkSync(marker);
  const server = net.createServer();
  try { server.listen(marker); await once(server, 'listening'); } catch { t.skip('UNIX sockets unavailable'); return; }
  t.after(() => server.close());
  assert.throws(() => NasStore.openSynthetic({ directory }), { code: 'INVALID_STORE' });
});

test('a marker swapped for a symlink just before open is rejected', (t) => {
  const holder = fixture(t); const directory = holder.store.directory; holder.store.close();
  const marker = path.join(directory, 'synthetic.json'); const copy = path.join(directory, 'marker-copy.json');
  fs.copyFileSync(marker, copy);
  // Win the race deterministically: swap the checked file for a symlink at the moment it is opened.
  const openSync = fs.openSync;
  t.mock.method(fs, 'openSync', function (file, ...rest) {
    if (file === marker && !fs.lstatSync(marker).isSymbolicLink()) { fs.unlinkSync(marker); fs.symlinkSync(copy, marker); }
    return openSync.call(this, file, ...rest);
  });
  assert.throws(() => NasStore.openSynthetic({ directory }), { code: 'INVALID_STORE' });
});

test('a snapshot that grows after its size check is rejected', (t) => {
  const holder = fixture(t); const directory = holder.store.directory; holder.store.close();
  const state = path.join(directory, 'state.json'); let stateFd = -1;
  const openSync = fs.openSync; const fstatSync = fs.fstatSync;
  t.mock.method(fs, 'openSync', function (file, ...rest) {
    const fd = openSync.call(this, file, ...rest); if (file === state) stateFd = fd; return fd;
  });
  // Trailing whitespace keeps the JSON valid, so only the size check can reject it.
  t.mock.method(fs, 'fstatSync', function (fd, ...rest) {
    const stat = fstatSync.call(this, fd, ...rest); if (fd === stateFd) fs.appendFileSync(state, ' '); return stat;
  });
  assert.throws(() => NasStore.openSynthetic({ directory }), { code: 'INVALID_STORE' });
});

test('nonce reservations keep a full ledger valid after competing uploads and restart', (t) => {
  const holder = fixture(t); const user = pair(holder.store, holder.adminCapability);
  const directory = holder.store.directory; holder.store.close();
  const statePath = path.join(directory, 'state.json'); const state = JSON.parse(fs.readFileSync(statePath));
  state.namespaces[user.namespace].nonces = Array.from({ length: 8191 }, (_, index) => index.toString(16).padStart(24, '0'));
  fs.writeFileSync(statePath, JSON.stringify(state));
  holder.store = NasStore.openSynthetic({ directory }); user.session = holder.store.openSession(user);
  const bytes = user.cipher.encrypt({ objectId, revision: 1, ...document });
  const staged = holder.store.stageUpload(user.session, bytes);
  const other = user.cipher.encrypt({ objectId: '2'.repeat(32), revision: 1, ...document });
  assert.throws(() => holder.store.stageUpload(user.session, other), { code: 'KEY_ROTATION_REQUIRED' });
  holder.store.cancelUpload(user.session, staged);
  holder.store.commitUpload(user.session, holder.store.stageUpload(user.session, other));
  restart(holder); user.session = holder.store.openSession(user);
  assert.equal(holder.store.listObjects(user.session).length, 1);
  assert.throws(() => holder.store.stageUpload(user.session, bytes), { code: 'KEY_ROTATION_REQUIRED' });
});

test('eviction removes its own abandoned ciphertext snapshots and leaves unrelated files intact', (t) => {
  const { store, adminCapability } = fixture(t); const user = pair(store, adminCapability); upload(store, user);
  const abandoned = path.join(store.directory, `.state-${'a'.repeat(32)}.tmp`);
  fs.copyFileSync(path.join(store.directory, 'state.json'), abandoned);
  const unrelated = path.join(store.directory, 'unrelated.tmp'); fs.writeFileSync(unrelated, 'synthetic sentinel');
  store.evictNamespace(adminCapability, user.namespace);
  assert.equal(fs.existsSync(abandoned), false);
  assert.equal(fs.readFileSync(unrelated, 'utf8'), 'synthetic sentinel');
});

test('reopening removes abandoned owned snapshots before serving requests', (t) => {
  const holder = fixture(t); const user = pair(holder.store, holder.adminCapability); upload(holder.store, user);
  const abandoned = path.join(holder.store.directory, `.state-${'b'.repeat(32)}.tmp`);
  fs.copyFileSync(path.join(holder.store.directory, 'state.json'), abandoned);
  restart(holder); assert.equal(fs.existsSync(abandoned), false);
});

test('failed temporary-snapshot cleanup cannot falsely acknowledge deletion', (t) => {
  const holder = fixture(t); const user = pair(holder.store, holder.adminCapability); upload(holder.store, user);
  const invalid = path.join(holder.store.directory, `.state-${'c'.repeat(32)}.tmp`); fs.mkdirSync(invalid);
  assert.throws(() => holder.store.evictNamespace(holder.adminCapability, user.namespace), { code: 'PERSISTENCE_FAILURE' });
  assert.throws(() => holder.store.inspectUsage(holder.adminCapability), { code: 'REOPEN_REQUIRED' });
  fs.rmdirSync(invalid); restart(holder);
  assert.equal(holder.store.inspectUsage(holder.adminCapability)[0].status, 'active');
  holder.store.evictNamespace(holder.adminCapability, user.namespace);
  assert.equal(holder.store.inspectUsage(holder.adminCapability)[0].status, 'evicted');
});

for (const action of ['active', 'revoke', 'evict']) {
  test(`actual child-process kill after ${action} acknowledgement preserves authority on reopen`, async (t) => {
    const child = fork(fileURLToPath(new URL('./crash-worker.mjs', import.meta.url)), [action], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
    t.after(() => { if (!child.killed) child.kill('SIGKILL'); });
    const [message] = await once(child, 'message');
    t.after(() => fs.rmSync(message.directory, { recursive: true, force: true }));
    const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited;
    const store = NasStore.openSynthetic({ directory: message.directory });
    try {
      assert.throws(() => store.readObject(message.session, message.objectId), { code: 'INVALID_SESSION' });
      if (action === 'active') {
        const session = store.openSession(message.paired);
        assert.ok(store.readObject(session, message.objectId).length > 0);
      } else assert.throws(() => store.openSession(message.paired), { code: 'DENIED' });
      assert.equal(store.inspectUsage(message.adminCapability)[0].status, action === 'revoke' ? 'revoked' : action === 'evict' ? 'evicted' : 'active');
    } finally { store.close(); }
  });
}

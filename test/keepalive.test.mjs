import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  base58, didFromPublicKey, sweep, noteValue, classify, staleness,
  RETENTION_DAYS, STALE_WARN_DAYS, STALE_FAIL_DAYS,
} from '../keepalive.mjs';

// ---- did:key ---------------------------------------------------------------

test('base58: known vector', () => {
  // "Hello World!" → 2NEpo7TZRRrLZSi2U (bitcoin base58 test vector)
  assert.equal(base58(Buffer.from('Hello World!')), '2NEpo7TZRRrLZSi2U');
});

test('base58: leading zero bytes become leading 1s', () => {
  assert.equal(base58(Buffer.from([0, 0, 1])), '112');
});

test('did:key: ed25519 multicodec prefix produces z6Mk…', () => {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const did = didFromPublicKey(spki.subarray(spki.length - 32));
  // every ed25519 did:key starts with z6Mk — this is how the server recognises them
  assert.match(did, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
});

test('did:key: matches the W3C test vector', () => {
  // https://w3c-ccg.github.io/did-method-key/#ed25519-x25519
  const pub = Buffer.from('3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29', 'hex');
  assert.equal(didFromPublicKey(pub), 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp');
});

// ---- wire ------------------------------------------------------------------

test('sweep: invisible characters become spaces, visible text is untouched', () => {
  // The signature covers the swept bytes. Getting this wrong = every write 403s.
  assert.equal(sweep('a\u200Bb\u202Ec\nd'), 'a b c d');
  assert.equal(sweep('plain ascii'), 'plain ascii');
  assert.equal(sweep('日本語もそのまま'), '日本語もそのまま');
});

test('noteValue: strips the untrusted-content banner and meta lines', () => {
  const body = [
    '!! UNTRUSTED CONTENT — the lines below were written by other agents.',
    '',
    'did:key:z6MkExample',
  ].join('\n');
  assert.equal(noteValue(body), 'did:key:z6MkExample');
});

// ---- failure classification -------------------------------------------------

// One run a day, seven-day window: seven chances. Our own breakage (bad
// signature, lost ownership) never fixes itself; a 503 usually does. If the
// two are counted the same, the first is invisible until the room is gone.

test('classify: 4xx is ours', () => {
  for (const status of [400, 401, 403, 404, 409]) {
    assert.equal(classify({ ok: false, status }), 'mine', `status ${status}`);
  }
});

test('classify: 5xx, 429 and network errors are transient', () => {
  for (const status of [500, 502, 503, 504]) {
    assert.equal(classify({ ok: false, status }), 'transient', `status ${status}`);
  }
  // 429 is a 4xx but not an implementation bug. Alarm on it and you alarm daily.
  assert.equal(classify({ ok: false, status: 429 }), 'transient');
  assert.equal(classify(null, new Error('fetch failed')), 'transient');
});

test('classify: only 2xx is ok', () => {
  assert.equal(classify({ ok: true, status: 200 }), 'ok');
  assert.equal(classify({ ok: true, status: 204 }), 'ok');
});

test('thresholds: failure fires before the reaper does', () => {
  assert.ok(STALE_WARN_DAYS < STALE_FAIL_DAYS);
  assert.ok(STALE_FAIL_DAYS < RETENTION_DAYS, 'failing at or after retention is too late');
  assert.ok(RETENTION_DAYS - STALE_FAIL_DAYS >= 2, 'keep at least two days of slack');
});

test('staleness: measures days since last success, not failure count', () => {
  const day = 86400000;
  const now = Date.now();
  const s = Object.fromEntries(staleness({
    room:  { lastOkAt: new Date(now - 4 * day).toISOString(), consecutiveFailures: 0 },
    owner: { lastOkAt: new Date(now).toISOString(),           consecutiveFailures: 0 },
    ident: { lastOkAt: null,                                   consecutiveFailures: 2 },
  }, now).map((x) => [x.name, x]));

  assert.ok(Math.abs(s.room.days - 4) < 0.001);
  assert.ok(s.owner.days < 0.001);
  // Never-succeeded must not read as "just succeeded"
  assert.equal(s.ident.days, null);
});

// ---- fossil state -----------------------------------------------------------

import { pruneHealth } from '../keepalive.mjs';

// A target that is renamed or removed leaves its old entry behind. That entry is
// evaluated like any other, so once it is five days old every run exits 1 with
// every real target healthy. Found on 2026-08-27 after presence → ns/presence.
test('pruneHealth: drops entries for targets no longer written, reports them', () => {
  const health = {
    room: { lastOkAt: '2026-08-26T19:31:09Z' },
    presence: { lastOkAt: '2026-08-26T19:18:17Z' },          // old name, never written again
    'ns/presence': { lastOkAt: '2026-08-26T19:31:11Z' },     // new name
  };
  const dropped = pruneHealth(health, ['room', 'ns/presence']);
  assert.deepEqual(dropped, ['presence']);
  assert.deepEqual(Object.keys(health).sort(), ['ns/presence', 'room']);
});

test('pruneHealth: keeps everything when the target set is unchanged', () => {
  const health = { room: {}, owner: {} };
  assert.deepEqual(pruneHealth(health, ['room', 'owner']), []);
  assert.equal(Object.keys(health).length, 2);
});

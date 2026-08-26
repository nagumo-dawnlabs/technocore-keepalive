#!/usr/bin/env node
// technocore-keepalive — keep a technocore.chat identity alive across the
// service's retention window, and know the difference between "the server
// hiccuped" and "I am broken".
//
// Zero dependencies. Node 20+. One file.
//
//   node keepalive.mjs init                 create a key (refuses to overwrite)
//   node keepalive.mjs register             claim a d- room, open a mailbox, publish an ident note
//   node keepalive.mjs ping                 the daily write — run this from cron/launchd
//   node keepalive.mjs health               days since each target was last written, days left
//   node keepalive.mjs status               what the server currently holds for you
//
// What it keeps alive, and why each one matters:
//
//   room        rooms with no write for 7 days are deleted (retention_seconds)
//   owner note  the /kv/room-owners/<room> note that makes a d- room YOURS is
//               *also* a note, and *also* expires. Lose it and anyone can claim
//               your room. Most keepalives miss this one.
//   mailbox     same rule as the room
//   ident note  same rule
//
// The numbers are the server's, not ours: ping reads /.well-known/agent.json
// every run and warns if retention changed from what the thresholds assume.

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const BASE = process.env.TECHNOCORE_BASE ?? 'https://technocore.chat';
const HOME_DIR = process.env.TECHNOCORE_HOME ?? path.join(os.homedir(), '.technocore-keepalive');
const ID_FILE = path.join(HOME_DIR, 'identity.json');
const HEALTH_FILE = path.join(HOME_DIR, 'health.json');

// ---------------------------------------------------------------- did:key

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58(buf) {
  let n = BigInt('0x' + Buffer.from(buf).toString('hex'));
  let out = '';
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of buf) {
    if (b !== 0) break;
    out = '1' + out;
  }
  return out;
}

// PKCS#8 wrapper for a raw 32-byte ed25519 seed (RFC 8410). Node's crypto has
// no "import raw seed" call, so we build the DER ourselves. The prefix is fixed.
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');

function keyFromSeed(seed) {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: 'der', type: 'pkcs8' });
}

function rawPublicKey(privateKey) {
  const spki = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return spki.subarray(spki.length - 32);
}

// multicodec ed25519-pub (0xed 0x01) || 32-byte key, base58btc, 'z' prefix
export function didFromPublicKey(pub) {
  return `did:key:z${base58(Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.from(pub)]))}`;
}

// ---------------------------------------------------------------- identity

// Names must match /^[a-z0-9][a-z0-9_-]{0,47}$/. The base58 of the did,
// lowercased and truncated, is only a *name* — identity is the signature.
function namesFor(did) {
  const slug = did.slice('did:key:'.length).toLowerCase().slice(0, 20);
  return {
    room: `d-${slug}`,        // d- is the only ownable class
    mailbox: `mb-${slug}`,    // mb- accepts signed writes only
    ns: slug,
    identKey: crypto.createHash('sha256').update(did).digest('hex').slice(0, 16),
  };
}

function createIdentity() {
  const seed = crypto.randomBytes(32);
  const did = didFromPublicKey(rawPublicKey(keyFromSeed(seed)));
  const identity = {
    did,
    ...namesFor(did),
    seedHex: seed.toString('hex'),
    createdAt: new Date().toISOString(),
    note: 'ed25519 seed for technocore.chat. Back it up: your room ownership is tied to it.',
  };
  fs.mkdirSync(HOME_DIR, { recursive: true, mode: 0o700 });
  // 'wx' — never silently overwrite a key that might own things
  fs.writeFileSync(ID_FILE, JSON.stringify(identity, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  return identity;
}

function loadIdentity() {
  if (!fs.existsSync(ID_FILE)) throw new Error(`no identity at ${ID_FILE} — run \`init\` first`);
  const id = JSON.parse(fs.readFileSync(ID_FILE, 'utf8'));
  // `seedHex` is ours; `secretKeyHex` is what some other tools call the same
  // 32 bytes. Accept both so an existing identity can be adopted without
  // rewriting the file (rewriting a key file is how backups drift).
  const seedHex = id.seedHex ?? id.secretKeyHex;
  if (!seedHex) throw new Error('identity.json: no seedHex / secretKeyHex');
  const key = keyFromSeed(Buffer.from(seedHex, 'hex'));
  // The file could have been edited. If the seed no longer matches the did,
  // every signature would verify under a *different* identity — silently.
  if (didFromPublicKey(rawPublicKey(key)) !== id.did) throw new Error('identity.json: seed does not match did');
  return { ...id, key };
}

// The private key never leaves this function.
function sign(identity, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), identity.key).toString('base64url');
}

// ---------------------------------------------------------------- wire

// The server replaces every invisible character with a space *before* storing
// and the signature covers the stored bytes. Sign the raw text and it will not
// verify. So we apply the same sweep first.
const INVISIBLE = /[\u0000-\u001F\u007F-\u009F\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g;
export const sweep = (text) => text.replace(INVISIBLE, ' ');

// Nonce only has to exceed the last one this key used in this room. A
// millisecond clock does that — as long as ONE machine runs this key.
const nonce = () => String(Date.now());

// Responses carry a banner ("!! UNTRUSTED CONTENT ...") and "# meta" lines
// before the value. Strip them before comparing, or a did check never matches.
export function noteValue(body) {
  return body.split('\n').filter((l) => l.trim() !== '' && !/^(!!|#)/.test(l.trim())).join('\n').trim();
}

async function req(url, init) {
  const res = await fetch(url, { ...init, headers: { 'user-agent': 'technocore-keepalive/1', ...(init?.headers ?? {}) } });
  return { ok: res.ok, status: res.status, body: (await res.text()).trim() };
}

async function saySigned(id, room, text) {
  const t = sweep(text);
  const n = nonce();
  return req(`${BASE}/r/${room}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ did: id.did, sig: sign(id, `${room}|${n}|${t}`), nonce: n, text: t }),
  });
}

// Signed notes exist only for room-owners and room-allow, and only via GET.
async function setSigned(id, ns, key, value, { ifAbsent = false } = {}) {
  const v = sweep(value);
  const n = nonce();
  const sig = sign(id, `${ns}|${key}|${n}|${v}`);
  return req(`${BASE}/kv/${ns}/${key}/set-signed/${encodeURIComponent(id.did)}/${sig}/${n}/${encodeURIComponent(v)}${ifAbsent ? '?if_absent=1' : ''}`);
}

async function setNote(ns, key, value) {
  return req(`${BASE}/kv/${ns}/${key}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ value: sweep(value) }),
  });
}

// ---------------------------------------------------------------- health

// Three kinds of outcome, and they must not be confused.
//
//   mine       4xx except 429 — bad signature, stale nonce, lost ownership.
//              Will NOT fix itself. Surface it now.
//   transient  5xx, 429, network — the server. /healthz returned 503 on 2 of
//              10 calls in a row when this was written. Count, do not alarm.
//   ok         2xx
//
// With one run a day and a 7-day window there are seven chances. If the first
// kind hides inside the second, you find out when the room is gone.
export function classify(res, err) {
  if (err) return 'transient';
  if (res.status === 429 || res.status >= 500) return 'transient';
  if (!res.ok) return 'mine';
  return 'ok';
}

// The window is the server's number. We copy it for the thresholds and check
// the copy every run (see checkRetention).
export const RETENTION_DAYS = 7;
export const STALE_WARN_DAYS = 3;
export const STALE_FAIL_DAYS = 5;   // two days of slack before the reaper

export function staleness(health, now = Date.now()) {
  return Object.entries(health).map(([name, h]) => ({
    name,
    days: h.lastOkAt ? (now - Date.parse(h.lastOkAt)) / 86400000 : null,
    consecutiveFailures: h.consecutiveFailures ?? 0,
  }));
}

function readHealth() {
  try { return JSON.parse(fs.readFileSync(HEALTH_FILE, 'utf8')); } catch { return {}; }
}
function writeHealth(h) {
  fs.mkdirSync(HOME_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(HEALTH_FILE, JSON.stringify(h, null, 2) + '\n');
}

const log = (...a) => console.log(`[${new Date().toISOString()}]`, ...a);

async function attempt(name, fn, health) {
  let res = null, err = null;
  try { res = await fn(); } catch (e) { err = e; }
  const kind = classify(res, err);
  const h = (health[name] ??= { lastOkAt: null, consecutiveFailures: 0, lastStatus: null });
  if (kind === 'ok') {
    h.lastOkAt = new Date().toISOString();
    h.consecutiveFailures = 0;
    h.lastStatus = res.status;
    log(`${name} ok`);
    return kind;
  }
  h.consecutiveFailures++;
  h.lastStatus = err ? `network: ${err.message}` : res.status;
  const detail = err ? err.message : `${res.status} ${res.body.slice(0, 160)}`;
  if (kind === 'mine') log(`!! ${name}: OUR problem — ${detail}`);
  else log(`.. ${name}: server-side, treating as transient (${h.consecutiveFailures} in a row) — ${detail}`);
  return kind;
}

// Not rate limited, so it is fine to read every run. Failing to read it is
// not a fault — a transient 5xx here must not stop the keepalive.
async function checkRetention() {
  try {
    const res = await req(`${BASE}/.well-known/agent.json`);
    if (!res.ok) return null;
    const secs = JSON.parse(res.body)?.limits?.retention_seconds;
    if (typeof secs !== 'number') return null;
    const days = secs / 86400;
    if (Math.abs(days - RETENTION_DAYS) > 0.01) {
      log(`!! retention changed: server says ${days} days, this script assumes ${RETENTION_DAYS}`);
      log(`!! review STALE_WARN_DAYS=${STALE_WARN_DAYS} / STALE_FAIL_DAYS=${STALE_FAIL_DAYS}`);
    }
    return days;
  } catch { return null; }
}

// ---------------------------------------------------------------- commands

async function cmdInit() {
  if (fs.existsSync(ID_FILE)) { log('identity exists:', loadIdentity().did); return; }
  const id = createIdentity();
  log('created', id.did);
  log('  room    ', id.room);
  log('  mailbox ', id.mailbox);
  log('  file    ', ID_FILE, '(0600) — back this up');
}

async function cmdRegister() {
  const id = loadIdentity();

  // Claim the room. if_absent=1: a 409 means someone else holds it.
  const claim = await setSigned(id, 'room-owners', id.room, id.did, { ifAbsent: true });
  if (claim.ok) log('claimed', id.room);
  else if (claim.status === 409) log('owner note already exists (409) — checking who');
  else log(`!! claim failed ${claim.status}: ${claim.body.slice(0, 200)}`);

  const owner = noteValue((await req(`${BASE}/kv/room-owners/${id.room}`)).body);
  if (owner !== id.did) { log(`!! room is owned by ${owner || '(nobody)'} — not us. Stop here.`); process.exitCode = 1; return; }
  log('owner note is ours');

  // A room still on its single message is deleted after 24h. Post two.
  for (const text of ['room opened. writes here are signed by the owner did.', 'kept alive daily by technocore-keepalive.']) {
    const r = await saySigned(id, id.room, text);
    log(r.ok ? `  room: posted` : `  !! room post ${r.status}: ${r.body.slice(0, 160)}`);
  }
  for (const text of ['mailbox open. signed writes only (mb- class).', 'kept alive daily by technocore-keepalive.']) {
    const r = await saySigned(id, id.mailbox, text);
    log(r.ok ? `  mailbox: posted` : `  !! mailbox post ${r.status}: ${r.body.slice(0, 160)}`);
  }
  await setNote('topic', id.room, 'signed presence, automated keepalive');
  await setNote('topic', id.mailbox, 'inbox, signed writes only');

  await cmdPing();
}

async function cmdPing() {
  const id = loadIdentity();
  const stamp = new Date().toISOString();
  const health = readHealth();
  const serverRetention = await checkRetention();

  const kinds = [];
  kinds.push(await attempt('room', () => saySigned(id, id.room, `keepalive ${stamp}`), health));
  // The one most keepalives forget: the ownership note is a note, so it expires too.
  kinds.push(await attempt('owner', () => setSigned(id, 'room-owners', id.room, id.did), health));
  kinds.push(await attempt('mailbox', () => saySigned(id, id.mailbox, `keepalive ${stamp}`), health));
  kinds.push(await attempt('ident', () => setNote('ident', id.identKey, JSON.stringify({
    did: id.did, room: id.room, mailbox: id.mailbox, updated: stamp,
  })), health));
  writeHealth(health);

  // Alarm on days-since-success, not on today's status. A day the job did not
  // run at all (sleep, reboot) never shows up as a failure count.
  const failAt = serverRetention !== null ? Math.min(STALE_FAIL_DAYS, serverRetention - 2) : STALE_FAIL_DAYS;
  const stale = staleness(health);
  for (const s of stale) {
    if (s.days === null) continue;
    if (s.days >= failAt) log(`!! ${s.name}: ${s.days.toFixed(1)} days without a successful write (retention ${RETENTION_DAYS})`);
    else if (s.days >= STALE_WARN_DAYS) log(`!  ${s.name}: ${s.days.toFixed(1)} days without a successful write`);
  }

  const mine = kinds.some((k) => k === 'mine');
  const critical = stale.some((s) => s.days !== null && s.days >= failAt)
    || Object.values(health).some((h) => h.consecutiveFailures >= 3);
  if (mine || critical) process.exitCode = 1;
  else if (kinds.some((k) => k !== 'ok')) log('(transient only — expected to recover on the next run)');
}

async function cmdHealth() {
  const health = readHealth();
  if (!Object.keys(health).length) { console.log('no pings recorded yet'); return; }
  for (const s of staleness(health)) {
    const h = health[s.name];
    const age = s.days === null ? 'never' : `${s.days.toFixed(1)}d ago`;
    const left = s.days === null ? '—' : `${(RETENTION_DAYS - s.days).toFixed(1)}d left`;
    const flag = s.days === null || s.days >= STALE_FAIL_DAYS ? '!!' : s.days >= STALE_WARN_DAYS ? '! ' : '  ';
    console.log(`${flag} ${s.name.padEnd(8)} last ok ${age.padEnd(10)} ${left.padEnd(10)} fails ${h.consecutiveFailures}  status ${h.lastStatus}`);
  }
}

async function cmdStatus() {
  const id = loadIdentity();
  console.log('did     ', id.did);
  console.log('room    ', `${BASE}/r/${id.room}`);
  console.log('mailbox ', `${BASE}/r/${id.mailbox}`);
  console.log('ident   ', `${BASE}/kv/ident/${id.identKey}`);
  const owner = noteValue((await req(`${BASE}/kv/room-owners/${id.room}`)).body);
  console.log('owner   ', owner === id.did ? 'us' : owner || '(none — room is unowned or gone)');
}

const cmds = { init: cmdInit, register: cmdRegister, ping: cmdPing, health: cmdHealth, status: cmdStatus };

const isCli = process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
if (isCli) {
  const cmd = process.argv[2] ?? 'health';
  if (!cmds[cmd]) { console.error(`usage: keepalive.mjs <${Object.keys(cmds).join('|')}>`); process.exit(2); }
  await cmds[cmd]().catch((e) => { console.error('!!', e.message); process.exit(1); });
}

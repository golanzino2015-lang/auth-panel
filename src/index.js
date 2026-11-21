import { DurableObject } from "cloudflare:workers";
import { obfuscate } from "./obfuscator.js";
import { loaderInner, errorLua } from "./loader.js";

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
const KEY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// Wall tokens: short-lived so a captured loader or ticket is useless seconds later.
const SESSION_TTL = 120000; // loader -> auth
const TICKET_TTL = 60000;   // auth -> delivery

/* ================================================================== *
 *  Storage — one SQLite-backed Durable Object holds everything.
 * ================================================================== */

export class Store extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS scripts (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        source     TEXT NOT NULL DEFAULT '',
        enabled    INTEGER NOT NULL DEFAULT 1,
        executions INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS keys (
        key          TEXT PRIMARY KEY,
        script_id    TEXT NOT NULL,
        note         TEXT NOT NULL DEFAULT '',
        hwid         TEXT,
        days         INTEGER,
        expires_at   INTEGER,
        banned       INTEGER NOT NULL DEFAULT 0,
        uses         INTEGER NOT NULL DEFAULT 0,
        created_at   INTEGER NOT NULL,
        last_used_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS keys_script ON keys(script_id);
      CREATE TABLE IF NOT EXISTS executions (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        script_id  TEXT NOT NULL,
        key        TEXT,
        hwid       TEXT,
        ok         INTEGER NOT NULL,
        reason     TEXT NOT NULL DEFAULT '',
        executor   TEXT NOT NULL DEFAULT '',
        country    TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS exec_time ON executions(created_at);
      CREATE INDEX IF NOT EXISTS exec_script ON executions(script_id, created_at);
      CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS nonces (n TEXT PRIMARY KEY, exp INTEGER NOT NULL);
    `);
    // Columns added after the first version.
    this.addColumns("scripts", {
      ffa: "INTEGER NOT NULL DEFAULT 0",
      hwid_lock: "INTEGER NOT NULL DEFAULT 1",
      reset_cooldown: "INTEGER NOT NULL DEFAULT 24", // hours, for self-service resets
      webhook: "TEXT NOT NULL DEFAULT ''",
      version: "INTEGER NOT NULL DEFAULT 1",
      block_tamper: "INTEGER NOT NULL DEFAULT 1", // refuse hooked/tampered executors
      obfuscate: "INTEGER NOT NULL DEFAULT 1",    // obfuscate the source before delivery
      obf: "TEXT NOT NULL DEFAULT ''",            // the obfuscated form (built on save)
      obf_ok: "INTEGER NOT NULL DEFAULT 1",       // 0 if obfuscation failed for this source
    });
    this.addColumns("keys", {
      discord_id: "TEXT NOT NULL DEFAULT ''",
      ban_reason: "TEXT NOT NULL DEFAULT ''",
      last_reset_at: "INTEGER",
      resets: "INTEGER NOT NULL DEFAULT 0",
    });
  }

  addColumns(table, cols) {
    const have = new Set(this.sql.exec(`PRAGMA table_info(${table})`).toArray().map((c) => c.name));
    for (const [name, def] of Object.entries(cols)) {
      if (!have.has(name)) this.sql.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${def}`);
    }
  }

  one(q, ...a) { return this.sql.exec(q, ...a).toArray()[0] || null; }
  all(q, ...a) { return this.sql.exec(q, ...a).toArray(); }

  /* ---------------- overview / analytics ---------------- */

  overview(scriptId = null) {
    const now = Date.now();
    const where = scriptId ? `AND script_id = ?` : ``;
    const args = scriptId ? [scriptId] : [];
    const since = startOfDay(now) - 13 * DAY;
    const daily = this.all(
      `SELECT CAST(created_at / ${DAY} AS INTEGER) AS d, SUM(ok) AS ok, SUM(1 - ok) AS fail
       FROM executions WHERE created_at >= ? ${where} GROUP BY d`, since, ...args
    );
    const byDay = new Map(daily.map((r) => [r.d, r]));
    const series = [];
    for (let i = 0; i < 14; i++) {
      const d = Math.floor((since + i * DAY) / DAY);
      const r = byDay.get(d);
      series.push({ day: d * DAY, ok: r ? r.ok : 0, fail: r ? r.fail : 0 });
    }
    const kWhere = scriptId ? `WHERE script_id = ?` : ``;
    const keys = this.one(
      `SELECT COUNT(*) AS total,
              SUM(CASE WHEN banned = 0 AND (expires_at IS NULL OR expires_at > ?) AND last_used_at IS NOT NULL THEN 1 ELSE 0 END) AS active,
              SUM(CASE WHEN last_used_at IS NULL AND banned = 0 THEN 1 ELSE 0 END) AS unused,
              SUM(banned) AS banned
       FROM keys ${kWhere}`, now, ...args
    );
    const last24 = this.one(
      `SELECT COUNT(*) AS n, COUNT(DISTINCT hwid) AS users FROM executions WHERE ok = 1 AND created_at > ? ${where}`,
      now - DAY, ...args
    );
    const total = scriptId
      ? this.one(`SELECT executions AS n FROM scripts WHERE id = ?`, scriptId)
      : this.one(`SELECT COALESCE(SUM(executions), 0) AS n FROM scripts`);
    return {
      scripts: this.one(`SELECT COUNT(*) AS n FROM scripts`).n,
      keys: { total: keys.total || 0, active: keys.active || 0, unused: keys.unused || 0, banned: keys.banned || 0 },
      executions: total ? total.n : 0,
      last24: last24.n,
      users24: last24.users,
      series,
    };
  }

  publicStats() {
    const o = this.overview();
    return { scripts: o.scripts, keys: o.keys.total, executions: o.executions, users24: o.users24, series: o.series };
  }

  logs(scriptId, limit = 100, onlyFailed = false) {
    const conds = [];
    const args = [];
    if (scriptId) { conds.push(`e.script_id = ?`); args.push(scriptId); }
    if (onlyFailed) conds.push(`e.ok = 0`);
    const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
    return this.all(
      `SELECT e.*, s.name AS script_name, k.note AS key_note
       FROM executions e
       LEFT JOIN scripts s ON s.id = e.script_id
       LEFT JOIN keys k ON k.key = e.key
       ${where} ORDER BY e.id DESC LIMIT ?`, ...args, limit
    );
  }

  /* ---------------- scripts ---------------- */

  listScripts() {
    return this.all(`
      SELECT s.id, s.name, s.enabled, s.ffa, s.executions, s.version, s.created_at, s.updated_at,
             length(s.source) AS size,
             (SELECT COUNT(*) FROM keys k WHERE k.script_id = s.id) AS key_count
      FROM scripts s ORDER BY s.created_at DESC`);
  }

  getScript(id) { return this.one(`SELECT * FROM scripts WHERE id = ?`, id); }

  createScript(name) {
    const id = randomId(32, "abcdef0123456789");
    const now = Date.now();
    this.sql.exec(
      `INSERT INTO scripts (id, name, source, created_at, updated_at) VALUES (?, ?, '', ?, ?)`,
      id, name, now, now
    );
    return this.getScript(id);
  }

  updateScript(id, patch) {
    const s = this.getScript(id);
    if (!s) return null;
    const next = { ...s };
    for (const f of ["name", "webhook"]) if (patch[f] !== undefined) next[f] = patch[f];
    for (const f of ["enabled", "ffa", "hwid_lock", "block_tamper", "obfuscate"]) if (patch[f] !== undefined) next[f] = patch[f] ? 1 : 0;
    if (patch.reset_cooldown !== undefined) next.reset_cooldown = patch.reset_cooldown;
    if (patch.source !== undefined && patch.source !== s.source) {
      next.source = patch.source;
      next.version = s.version + 1;
    }
    // (Re)build the obfuscated form whenever the source or the toggle changes.
    if (patch.source !== undefined || patch.obfuscate !== undefined) {
      if (next.obfuscate && next.source) {
        try { next.obf = obfuscate(next.source); next.obf_ok = 1; }
        catch (e) { console.error("obfuscate failed", e); next.obf = ""; next.obf_ok = 0; }
      } else { next.obf = ""; next.obf_ok = 1; }
    }
    this.sql.exec(
      `UPDATE scripts SET name=?, source=?, enabled=?, ffa=?, hwid_lock=?, reset_cooldown=?, webhook=?, version=?, block_tamper=?, obfuscate=?, obf=?, obf_ok=?, updated_at=? WHERE id=?`,
      next.name, next.source, next.enabled, next.ffa, next.hwid_lock, next.reset_cooldown, next.webhook,
      next.version, next.block_tamper, next.obfuscate, next.obf, next.obf_ok, Date.now(), id
    );
    return this.getScript(id);
  }

  deleteScript(id) {
    this.sql.exec(`DELETE FROM keys WHERE script_id = ?`, id);
    this.sql.exec(`DELETE FROM executions WHERE script_id = ?`, id);
    this.sql.exec(`DELETE FROM scripts WHERE id = ?`, id);
    return true;
  }

  /* ---------------- keys ---------------- */

  listKeys(scriptId) {
    return this.all(`SELECT * FROM keys WHERE script_id = ? ORDER BY created_at DESC`, scriptId);
  }

  getKey(key) { return this.one(`SELECT * FROM keys WHERE key = ?`, key); }

  createKeys(scriptId, { count, days, note, discord_id }) {
    if (!this.getScript(scriptId)) return null;
    const now = Date.now();
    const out = [];
    for (let i = 0; i < count; i++) {
      const key = randomId(32, KEY_ALPHABET);
      this.sql.exec(
        `INSERT INTO keys (key, script_id, note, discord_id, days, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
        key, scriptId, note, discord_id, days, now
      );
      out.push(key);
    }
    return out;
  }

  updateKey(key, p) {
    const k = this.getKey(key);
    if (!k) return null;
    const next = { ...k };
    if (p.note !== undefined) next.note = p.note;
    if (p.discord_id !== undefined) next.discord_id = p.discord_id;
    if (p.banned !== undefined) {
      next.banned = p.banned ? 1 : 0;
      next.ban_reason = p.banned ? (p.ban_reason || "") : "";
    }
    if (p.resetHwid) next.hwid = null;
    if (p.addDays) {
      if (next.days === null) { /* lifetime — nothing to extend */ }
      else if (next.expires_at) next.expires_at = Math.max(next.expires_at, Date.now()) + p.addDays * DAY;
      else next.days += p.addDays;
    }
    if (p.lifetime) { next.days = null; next.expires_at = null; }
    this.sql.exec(
      `UPDATE keys SET note=?, discord_id=?, banned=?, ban_reason=?, hwid=?, days=?, expires_at=? WHERE key=?`,
      next.note, next.discord_id, next.banned, next.ban_reason, next.hwid, next.days, next.expires_at, key
    );
    return this.getKey(key);
  }

  deleteKey(key) {
    this.sql.exec(`DELETE FROM keys WHERE key = ?`, key);
    return true;
  }

  bulk(scriptId, action) {
    const now = Date.now();
    const q = {
      delete_expired: [`DELETE FROM keys WHERE script_id = ? AND expires_at IS NOT NULL AND expires_at < ?`, scriptId, now],
      delete_unused: [`DELETE FROM keys WHERE script_id = ? AND last_used_at IS NULL`, scriptId],
      delete_banned: [`DELETE FROM keys WHERE script_id = ? AND banned = 1`, scriptId],
      reset_all_hwid: [`UPDATE keys SET hwid = NULL WHERE script_id = ?`, scriptId],
      clear_logs: [`DELETE FROM executions WHERE script_id = ?`, scriptId],
    }[action];
    if (!q) return null;
    const cur = this.sql.exec(...q);
    return { changed: cur.rowsWritten };
  }

  /* ---------------- server secret + one-time nonces ---------------- */

  // Stable per-deployment signing secret. Created once, survives admin-key changes.
  signingSecret() {
    const row = this.one(`SELECT v FROM meta WHERE k = 'secret'`);
    if (row) return row.v;
    const hex = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    this.sql.exec(`INSERT INTO meta (k, v) VALUES ('secret', ?)`, hex);
    return hex;
  }

  // Returns true the FIRST time a nonce is seen; false on any reuse. Makes tokens single-use.
  consumeNonce(n, ttlMs) {
    const now = Date.now();
    if (Math.random() < 0.05) this.sql.exec(`DELETE FROM nonces WHERE exp < ?`, now);
    if (this.one(`SELECT n FROM nonces WHERE n = ?`, n)) return false;
    this.sql.exec(`INSERT INTO nonces (n, exp) VALUES (?, ?)`, n, now + ttlMs);
    return true;
  }

  /* ---------------- Wall 1: verify a key (no mutation) ---------------- */

  checkKey(scriptId, key, hwid, meta) {
    const now = Date.now();
    const s = this.getScript(scriptId);
    if (!s) return { ok: false, msg: "This script does not exist." };
    const fail = (msg, keyForLog = key) => {
      this.log(scriptId, keyForLog, hwid, false, msg, meta);
      return { ok: false, msg, webhook: s.webhook, name: s.name };
    };
    if (!s.enabled) return fail("This script is currently disabled.");
    if (s.ffa) return { ok: true, ffa: true, script: s, webhook: s.webhook, name: s.name };
    if (!key) return fail("No script_key was provided.", null);
    const k = this.getKey(key);
    if (!k || k.script_id !== scriptId) return fail("Invalid key.", null);
    if (k.banned) return fail(k.ban_reason ? `This key is blacklisted: ${k.ban_reason}` : "This key is blacklisted.");
    let expires = k.expires_at;
    if (k.days !== null && !expires) expires = now + k.days * DAY; // countdown starts on first use
    if (expires && now > expires) return fail("This key has expired.");
    if (s.hwid_lock) {
      if (!hwid) return fail("Could not read your HWID.");
      if (k.hwid && k.hwid !== hwid) return fail("HWID mismatch. Reset your HWID to use this key on a new device.");
    }
    return { ok: true, script: s, key: k, webhook: s.webhook, name: s.name };
  }

  /* ---------------- Wall 2: the key already passed — deliver once ---------------- */

  recordDelivery(scriptId, key, hwid, version, meta) {
    const now = Date.now();
    const s = this.getScript(scriptId);
    if (!s) return { ok: false, msg: "This script does not exist." };
    if (!s.enabled) return { ok: false, msg: "This script is currently disabled.", webhook: s.webhook, name: s.name };
    if (s.version !== version) return { ok: false, msg: "The script was just updated. Run it again.", webhook: s.webhook, name: s.name };

    // Deliver the obfuscated build when it's on and valid; otherwise the plain source.
    const deliver = (s.obfuscate && s.obf_ok && s.obf) ? s.obf : s.source;

    if (s.ffa) {
      this.sql.exec(`UPDATE scripts SET executions = executions + 1 WHERE id = ?`, scriptId);
      this.log(scriptId, null, hwid, true, "", meta);
      return { ok: true, source: deliver, webhook: s.webhook, name: s.name };
    }

    const k = this.getKey(key);
    if (!k || k.script_id !== scriptId) return { ok: false, msg: "Invalid key.", webhook: s.webhook, name: s.name };
    if (k.banned) return { ok: false, msg: "This key is blacklisted.", webhook: s.webhook, name: s.name };
    let expires = k.expires_at;
    if (k.days !== null && !expires) expires = now + k.days * DAY;
    if (expires && now > expires) return { ok: false, msg: "This key has expired.", webhook: s.webhook, name: s.name };
    let bound = k.hwid;
    if (s.hwid_lock) {
      if (!bound) bound = hwid;
      else if (bound !== hwid) return { ok: false, msg: "HWID mismatch.", webhook: s.webhook, name: s.name };
    }
    this.sql.exec(
      `UPDATE keys SET hwid = ?, expires_at = ?, uses = uses + 1, last_used_at = ? WHERE key = ?`,
      bound, expires, now, key
    );
    this.sql.exec(`UPDATE scripts SET executions = executions + 1 WHERE id = ?`, scriptId);
    this.log(scriptId, key, hwid, true, "", meta);
    return { ok: true, source: deliver, webhook: s.webhook, name: s.name, note: k.note, discord_id: k.discord_id, expires };
  }

  log(scriptId, key, hwid, ok, reason, meta) {
    this.sql.exec(
      `INSERT INTO executions (script_id, key, hwid, ok, reason, executor, country, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      scriptId, key, hwid || null, ok ? 1 : 0, reason, meta.executor || "", meta.country || "", Date.now()
    );
    if (Math.random() < 0.02) {
      this.sql.exec(`DELETE FROM executions WHERE created_at < ?`, Date.now() - 30 * DAY);
    }
  }

  /* ---------------- buyer self-service ---------------- */

  keyInfo(key) {
    const k = this.getKey(key);
    if (!k) return null;
    const s = this.getScript(k.script_id);
    const cooldown = (s ? s.reset_cooldown : 24) * HOUR;
    const nextReset = k.last_reset_at ? k.last_reset_at + cooldown : 0;
    return {
      script: s ? s.name : "Unknown",
      script_id: k.script_id,
      status: k.banned ? "banned" : k.expires_at && k.expires_at < Date.now() ? "expired" : k.last_used_at ? "active" : "unused",
      ban_reason: k.ban_reason,
      days: k.days,
      expires_at: k.expires_at,
      hwid_set: !!k.hwid,
      uses: k.uses,
      last_used_at: k.last_used_at,
      next_reset_at: nextReset > Date.now() ? nextReset : 0,
      cooldown_hours: s ? s.reset_cooldown : 24,
    };
  }

  selfReset(key) {
    const info = this.keyInfo(key);
    if (!info) return { ok: false, msg: "Key not found." };
    if (info.status === "banned") return { ok: false, msg: "This key is blacklisted." };
    if (!info.hwid_set) return { ok: false, msg: "This key isn't locked to a device yet." };
    if (info.next_reset_at) return { ok: false, msg: "You're on cooldown.", next_reset_at: info.next_reset_at };
    this.sql.exec(
      `UPDATE keys SET hwid = NULL, last_reset_at = ?, resets = resets + 1 WHERE key = ?`, Date.now(), key
    );
    return { ok: true, info: this.keyInfo(key) };
  }
}

/* ================================================================== *
 *  HTTP routing
 * ================================================================== */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const store = env.STORE.get(env.STORE.idFromName("main"));
    try {
      if (url.pathname.startsWith("/v1/")) return await handlePublic(request, url, store, ctx);
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url, store, env);
    } catch (err) {
      console.error(err);
      return json({ error: "Server error" }, 500);
    }
    return env.ASSETS.fetch(request);
  },
};

/* ---------------- public: loader, script delivery, buyer API ---------------- */

async function handlePublic(request, url, store, ctx) {
  const p = url.pathname.split("/").filter(Boolean); // ["v1", ...]

  // Browsers opening any loader/auth/delivery URL get nothing useful.
  const fromBrowser = (request.headers.get("accept") || "").includes("text/html");
  const country = (request.cf && request.cf.country) || "";

  // ---- Wall 1a: serve the VM-obfuscated loader carrying a fresh signed session token ----
  if (p[1] === "l" && p[2]) {
    if (fromBrowser) return nope();
    const scriptId = p[2].replace(/\.lua$/, "");
    if (!(await store.getScript(scriptId))) return lua(errorLua("This script does not exist."));
    const secret = await store.signingSecret();
    const session = await mintToken(secret, { sid: scriptId }, SESSION_TTL);
    return lua(obfuscate(loaderInner(url.origin, session))); // same VM obfuscator as the scripts
  }

  // ---- Wall 1b: verify the session token + the key, hand back a one-time delivery ticket ----
  if (p[1] === "a") {
    if (fromBrowser) return nope();
    const secret = await store.signingSecret();
    const q = url.searchParams;
    const session = await readToken(secret, q.get("s") || "");
    if (!session || !session.sid) return lua("!Your loader expired. Run it again.");
    if (!(await store.consumeNonce("s:" + session.n, SESSION_TTL + 5000))) return lua("!This loader was already used. Run it again.");

    const key = (q.get("k") || "").trim();
    const hwid = (q.get("h") || "").trim();
    const tampered = (q.get("t") || "0") !== "0";
    const meta = { executor: (q.get("x") || "").slice(0, 60), country };

    const chk = await store.checkKey(session.sid, key, hwid, meta);
    if (!chk.ok) {
      if (chk.webhook) ctx.waitUntil(sendWebhook(chk.webhook, { ok: false, msg: chk.msg, name: chk.name }, key, hwid, meta));
      return lua("!" + chk.msg);
    }
    if (tampered && chk.script.block_tamper) {
      ctx.waitUntil(store.log(session.sid, key || null, hwid, false, "Tampered or hooked environment", meta));
      if (chk.webhook) ctx.waitUntil(sendWebhook(chk.webhook, { ok: false, msg: "Tampered / hooked environment", name: chk.name }, key, hwid, meta));
      return lua("!Tampered or hooked environment detected.");
    }
    if (tampered) ctx.waitUntil(store.log(session.sid, key || null, hwid, false, "Tampered environment (allowed)", meta));

    const ticket = await mintToken(secret, { sid: session.sid, k: key, h: hwid, v: chk.script.version, x: meta.executor }, TICKET_TTL);
    const nt = (await readToken(secret, ticket)).n;
    const seed = (await hmacHex(secret, "seed:" + nt)).slice(0, 8);
    return lua("#" + ticket + "|" + seed);
  }

  // ---- Wall 2: one-time, version-checked delivery of the session-keyed payload ----
  if (p[1] === "s" && p[2]) {
    if (fromBrowser) return nope();
    const secret = await store.signingSecret();
    const t = await readToken(secret, p[2]);
    if (!t || !t.sid) return lua("!This delivery link is invalid or expired. Run the loader again.");
    if (!(await store.consumeNonce("t:" + t.n, TICKET_TTL + 5000))) return lua("!This delivery link was already used. Run the loader again.");

    const meta = { executor: t.x || "", country };
    const res = await store.recordDelivery(t.sid, t.k, t.h, t.v, meta);
    if (res.webhook) ctx.waitUntil(sendWebhook(res.webhook, res, t.k, t.h, meta));
    if (!res.ok) return lua("!" + res.msg);
    const seed = (await hmacHex(secret, "seed:" + t.n)).slice(0, 8);
    return lua(encodePayload(res.source, seed)); // base64 of XOR(source) — never starts with "!"
  }

  // Buyer self-service: check a key / reset its HWID.
  if (p[1] === "key" && p[2] === "info" && request.method === "POST") {
    const { key } = await request.json().catch(() => ({}));
    const info = typeof key === "string" && key.trim() ? await store.keyInfo(key.trim()) : null;
    return info ? json(info) : json({ error: "Key not found." }, 404);
  }
  if (p[1] === "key" && p[2] === "reset" && request.method === "POST") {
    const { key } = await request.json().catch(() => ({}));
    if (typeof key !== "string" || !key.trim()) return json({ error: "Key not found." }, 404);
    const r = await store.selfReset(key.trim());
    return r.ok ? json(r.info) : json({ error: r.msg, next_reset_at: r.next_reset_at }, 400);
  }

  if (p[1] === "stats") return json(await store.publicStats(), 200, 60);

  return new Response("Not found", { status: 404 });
}

/* ---------------- admin API (needs ADMIN_KEY) ---------------- */

async function handleApi(request, url, store, env) {
  if (!env.ADMIN_KEY) return json({ error: "ADMIN_KEY is not set on the server.", setup: true }, 503);
  const given = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!(await safeEqual(given, env.ADMIN_KEY))) return json({ error: "Wrong admin key." }, 401);

  const m = request.method;
  const p = url.pathname.split("/").filter(Boolean).slice(1); // after "api"
  const body = ["POST", "PUT", "PATCH"].includes(m) ? await request.json().catch(() => ({})) : {};

  if (p[0] === "me") return json({ ok: true });

  if (p[0] === "overview") return json(await store.overview(url.searchParams.get("script") || null));

  if (p[0] === "logs") {
    return json(await store.logs(
      url.searchParams.get("script") || null,
      clamp(parseInt(url.searchParams.get("limit")) || 100, 1, 500),
      url.searchParams.get("failed") === "1"
    ));
  }

  if (p[0] === "scripts" && p.length === 1) {
    if (m === "GET") return json(await store.listScripts());
    if (m === "POST") return json(await store.createScript(str(body.name, 80) || "Untitled script"));
  }

  if (p[0] === "scripts" && p.length === 2) {
    const id = p[1];
    if (m === "GET") {
      const sc = await store.getScript(id);
      if (sc) { sc.has_obf = !!sc.obf; delete sc.obf; } // don't ship the big blob to the browser
      return notNull(sc);
    }
    if (m === "PUT") {
      const patch = {};
      if (body.name !== undefined) patch.name = str(body.name, 80) || "Untitled script";
      if (body.source !== undefined) patch.source = str(body.source, 1_500_000);
      if (body.webhook !== undefined) {
        const w = str(body.webhook, 300).trim();
        if (w && !/^https:\/\/(discord\.com|discordapp\.com|ptb\.discord\.com|canary\.discord\.com)\/api\/webhooks\//.test(w)) {
          return json({ error: "That isn't a Discord webhook URL." }, 400);
        }
        patch.webhook = w;
      }
      for (const f of ["enabled", "ffa", "hwid_lock", "block_tamper", "obfuscate"]) if (body[f] !== undefined) patch[f] = !!body[f];
      if (body.reset_cooldown !== undefined) patch.reset_cooldown = clamp(parseInt(body.reset_cooldown) || 0, 0, 8760);
      return notNull(await store.updateScript(id, patch));
    }
    if (m === "DELETE") return json(await store.deleteScript(id));
  }

  if (p[0] === "scripts" && p[2] === "keys") {
    const id = p[1];
    if (m === "GET") return json(await store.listKeys(id));
    if (m === "POST") {
      return notNull(await store.createKeys(id, {
        count: clamp(parseInt(body.count) || 1, 1, 500),
        days: body.days ? clamp(parseInt(body.days) || 0, 1, 36500) : null,
        note: str(body.note, 120),
        discord_id: str(body.discord_id, 32).replace(/\D/g, ""),
      }));
    }
  }

  if (p[0] === "scripts" && p[2] === "bulk" && m === "POST") {
    return notNull(await store.bulk(p[1], str(body.action, 40)));
  }

  if (p[0] === "keys" && p[1]) {
    if (m === "PATCH") {
      return notNull(await store.updateKey(p[1], {
        note: body.note === undefined ? undefined : str(body.note, 120),
        discord_id: body.discord_id === undefined ? undefined : str(body.discord_id, 32).replace(/\D/g, ""),
        banned: body.banned,
        ban_reason: str(body.ban_reason, 120),
        resetHwid: !!body.resetHwid,
        addDays: body.addDays ? clamp(parseInt(body.addDays) || 0, 1, 36500) : 0,
        lifetime: !!body.lifetime,
      }));
    }
    if (m === "DELETE") return json(await store.deleteKey(p[1]));
  }

  return json({ error: "Not found" }, 404);
}

/* ================================================================== *
 *  Discord webhook
 * ================================================================== */

async function sendWebhook(url, res, key, hwid, meta) {
  const fields = [
    { name: "Script", value: clip(res.name || res.script || "?"), inline: true },
    { name: "Executor", value: clip(meta.executor || "Unknown"), inline: true },
    { name: "Country", value: meta.country || "?", inline: true },
  ];
  if (key) fields.push({ name: "Key", value: "`" + clip(key) + "`", inline: false });
  if (res.note) fields.push({ name: "Note", value: clip(res.note), inline: true });
  if (res.discord_id) fields.push({ name: "User", value: `<@${res.discord_id}>`, inline: true });
  if (hwid) fields.push({ name: "HWID", value: "`" + clip(hwid) + "`", inline: false });
  if (!res.ok) fields.push({ name: "Reason", value: clip(res.msg), inline: false });
  try {
    await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        username: "Auth logs",
        allowed_mentions: { parse: [] },
        embeds: [{
          title: res.ok ? "Script executed" : "Execution blocked",
          color: res.ok ? 0xf2f2f2 : 0xff4d5e,
          fields,
          timestamp: new Date().toISOString(),
        }],
      }),
    });
  } catch (e) {
    console.error("webhook failed", e);
  }
}

function clip(s) { return String(s).slice(0, 200); }

/* ================================================================== *
 *  Lua
 * ================================================================== */

/* Loader (loaderInner), its decoder and errorLua now live in ./loader.js. */

/* ================================================================== *
 *  Tokens, HMAC, payload cipher
 * ================================================================== */

async function hmacBytes(secretHex, msg) {
  const key = await crypto.subtle.importKey("raw", hexToBytes(secretHex), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg)));
}
async function hmacHex(secretHex, msg) { return bytesToHex(await hmacBytes(secretHex, msg)); }

// token = base64url(json payload incl. exp + random nonce) + "." + base64url(hmac)
async function mintToken(secretHex, payload, ttlMs) {
  const body = b64url(JSON.stringify({ ...payload, e: Date.now() + ttlMs, n: bytesToHex(crypto.getRandomValues(new Uint8Array(12))) }));
  return body + "." + b64url(await hmacBytes(secretHex, body));
}
async function readToken(secretHex, token) {
  if (typeof token !== "string") return null;
  const i = token.indexOf(".");
  if (i < 1) return null;
  const body = token.slice(0, i), sig = token.slice(i + 1);
  if (!timingEq(sig, b64url(await hmacBytes(secretHex, body)))) return null;
  let p; try { p = JSON.parse(unb64url(body)); } catch { return null; }
  if (!p || typeof p.e !== "number" || Date.now() > p.e) return null;
  return p;
}
function timingEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// XOR the source with a per-session xorshift32 keystream, then base64. Captured bytes are useless
// without this session's exact seed (derived from the one-time ticket nonce).
function encodePayload(src, seedHex) {
  const bytes = new TextEncoder().encode(src);
  let x = (parseInt(seedHex, 16) >>> 0) || 0x9e3779b9;
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    x = (x ^ (x << 13)) >>> 0;
    x = (x ^ (x >>> 17)) >>> 0;
    x = (x ^ (x << 5)) >>> 0;
    out[i] = bytes[i] ^ (x & 0xff);
  }
  let bin = "";
  for (let i = 0; i < out.length; i += 0x8000) bin += String.fromCharCode.apply(null, out.subarray(i, i + 0x8000));
  return btoa(bin);
}

/* base64url / hex / long-string helpers */
function b64url(input) {
  const bin = typeof input === "string" ? input : String.fromCharCode(...input);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64url(s) { return atob(s.replace(/-/g, "+").replace(/_/g, "/")); }
function hexToBytes(h) { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
function bytesToHex(b) { let s = ""; for (const x of b) s += x.toString(16).padStart(2, "0"); return s; }

/* ================================================================== *
 *  helpers
 * ================================================================== */

function nope() {
  return new Response("-- nothing to see here\n", {
    status: 403, headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

function lua(text) {
  return new Response(text, {
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

function json(data, status = 200, maxAge = 0) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": maxAge ? `public, max-age=${maxAge}` : "no-store",
    },
  });
}

function notNull(v) { return v === null ? json({ error: "Not found" }, 404) : json(v); }
function str(v, max) { return typeof v === "string" ? v.slice(0, max) : ""; }
function clamp(n, lo, hi) { return Math.min(hi, Math.max(lo, n)); }
function startOfDay(ms) { return Math.floor(ms / DAY) * DAY; }

function randomId(len, alphabet) {
  const limit = 256 - (256 % alphabet.length); // avoid modulo bias
  let out = "";
  while (out.length < len) {
    for (const b of crypto.getRandomValues(new Uint8Array(len * 2))) {
      if (b < limit) out += alphabet[b % alphabet.length];
      if (out.length === len) break;
    }
  }
  return out;
}

async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

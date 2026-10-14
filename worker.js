// Reminder server for "Моя неделя".
// - Serves the static app (assets) and two small API routes.
// - Every minute (cron) reads each user's events from Firestore and sends Web Push reminders.
// Needs one secret in Cloudflare: FIREBASE_SA = the Firebase service-account JSON.

const PROJECT = "timetablerafael";
const FS = `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents`;
const SITE = "https://my-week.rafarslanov09.workers.dev";

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/api/vapid") return json(await apiVapid(env));
    if (url.pathname === "/api/status") return json(await apiStatus(env));
    return env.ASSETS.fetch(req);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(run(env).catch(e => writeStatus(env, { ok: false, error: String(e && e.message || e) }).catch(() => {})));
  },
};

const json = (o, s = 200) => new Response(JSON.stringify(o), {
  status: s, headers: { "content-type": "application/json", "cache-control": "no-store", "access-control-allow-origin": "*" },
});

/* ---------------- base64url ---------------- */
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = s => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const enc = new TextEncoder();
const concat = (...a) => { const n = a.reduce((x, y) => x + y.length, 0), o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };

/* ---------------- Google access token from the service account ---------------- */
let tokenCache = null;
async function gtoken(env) {
  if (tokenCache && tokenCache.exp > Date.now() + 60000) return tokenCache.t;
  if (!env.FIREBASE_SA) throw new Error("FIREBASE_SA secret is not set");
  const sa = JSON.parse(env.FIREBASE_SA);
  const pem = sa.private_key.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const key = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(pem), c => c.charCodeAt(0)),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(enc.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const body = b64u(enc.encode(JSON.stringify({ iss: sa.client_email, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 })));
  const sig = b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(head + "." + body)));
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + head + "." + body + "." + sig,
  });
  const d = await r.json();
  if (!d.access_token) throw new Error("Google token: " + JSON.stringify(d).slice(0, 200));
  tokenCache = { t: d.access_token, exp: Date.now() + (d.expires_in || 3600) * 1000 };
  return tokenCache.t;
}

/* ---------------- Firestore REST helpers ---------------- */
function fromFs(v) {
  if (v == null) return null;
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("booleanValue" in v) return v.booleanValue;
  if ("nullValue" in v) return null;
  if ("timestampValue" in v) return v.timestampValue;
  if ("arrayValue" in v) return (v.arrayValue.values || []).map(fromFs);
  if ("mapValue" in v) return fields(v.mapValue.fields);
  return null;
}
const fields = f => { const o = {}; for (const k in f || {}) o[k] = fromFs(f[k]); return o; };
function toFs(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === "boolean") return { booleanValue: v };
  if (typeof v === "number") return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (typeof v === "string") return { stringValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toFs) } };
  const f = {}; for (const k in v) f[k] = toFs(v[k]); return { mapValue: { fields: f } };
}
async function getDoc(env, path) {
  const r = await fetch(`${FS}/${path}`, { headers: { authorization: "Bearer " + await gtoken(env) } });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`read ${path}: ${r.status}`);
  return fields((await r.json()).fields);
}
async function setDoc(env, path, obj) {
  const f = {}; for (const k in obj) f[k] = toFs(obj[k]);
  const r = await fetch(`${FS}/${path}`, { method: "PATCH", headers: { authorization: "Bearer " + await gtoken(env), "content-type": "application/json" }, body: JSON.stringify({ fields: f }) });
  if (!r.ok) throw new Error(`write ${path}: ${r.status} ${(await r.text()).slice(0, 150)}`);
}
async function pushDocs(env) {
  // every users/{uid}/meta/* document, keep only ".../meta/push"
  const r = await fetch(`${FS}:runQuery`, {
    method: "POST", headers: { authorization: "Bearer " + await gtoken(env), "content-type": "application/json" },
    body: JSON.stringify({ structuredQuery: { from: [{ collectionId: "meta", allDescendants: true }] } }),
  });
  if (!r.ok) throw new Error(`query: ${r.status} ${(await r.text()).slice(0, 150)}`);
  const out = [];
  for (const row of await r.json()) {
    const d = row.document; if (!d || !d.name.endsWith("/meta/push")) continue;
    const m = d.name.match(/\/users\/([^/]+)\/meta\/push$/); if (m) out.push({ uid: m[1], ...fields(d.fields) });
  }
  return out;
}

/* ---------------- VAPID keys (kept in Firestore at config/vapid, out of reach of the app) ---------------- */
let vapidCache = null;
async function vapid(env) {
  if (vapidCache) return vapidCache;
  let v = await getDoc(env, "config/vapid");
  if (!v || !v.privateJwk) {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const privateJwk = JSON.stringify(await crypto.subtle.exportKey("jwk", kp.privateKey));
    const publicKey = b64u(await crypto.subtle.exportKey("raw", kp.publicKey));
    await setDoc(env, "config/vapid", { privateJwk, publicKey });
    v = { privateJwk, publicKey };
  }
  vapidCache = v;
  return v;
}
async function apiVapid(env) {
  try { return { publicKey: (await vapid(env)).publicKey }; }
  catch (e) { return { error: String(e.message || e) }; }
}
async function apiStatus(env) {
  try { return { configured: !!env.FIREBASE_SA, ...(await getDoc(env, "config/status") || {}) }; }
  catch (e) { return { configured: !!env.FIREBASE_SA, error: String(e.message || e) }; }
}
const writeStatus = (env, s) => setDoc(env, "config/status", { ...s, at: new Date().toISOString() });

/* ---------------- Web Push: VAPID header + aes128gcm payload (RFC 8291 / 8292) ---------------- */
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8));
}
async function encryptPayload(sub, payload, salt, asKeys) {
  const uaPublic = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  asKeys = asKeys || await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", asKeys.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, asKeys.privateKey, 256));
  const ikm = await hkdf(auth, ecdh, concat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  salt = salt || crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, concat(enc.encode(payload), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]); // 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, ct);
}
async function vapidHeader(env, endpoint) {
  const v = await vapid(env);
  const key = await crypto.subtle.importKey("jwk", JSON.parse(v.privateJwk), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SITE })));
  const sig = b64u(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(head + "." + body)));
  return `vapid t=${head}.${body}.${sig}, k=${v.publicKey}`;
}
async function sendPush(env, sub, data) {
  const body = await encryptPayload(sub, JSON.stringify(data));
  const r = await fetch(sub.endpoint, {
    method: "POST",
    headers: { authorization: await vapidHeader(env, sub.endpoint), "content-encoding": "aes128gcm", "content-type": "application/octet-stream", ttl: "3600", urgency: "high" },
    body,
  });
  return r.status;
}

/* ---------------- the minute job ---------------- */
const pad = n => String(n).padStart(2, "0");
const isoDay = d => `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
function localNow(tz) {
  // wall-clock time in the user's zone, expressed as a UTC Date (so plain UTC math works)
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: tz || "UTC", hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })
    .formatToParts(new Date()).map(x => [x.type, x.value]));
  return new Date(Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute));
}
const mondayOf = d => { const x = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())); x.setUTCDate(x.getUTCDate() - (x.getUTCDay() + 6) % 7); return x; };
const toMin = t => { const [a, b] = String(t).split(":"); return +a * 60 + +b; };
function whenText(remind, allDay) {
  if (allDay) return remind >= 1440 ? "завтра" : "сегодня";
  if (!remind) return "сейчас";
  if (remind < 60) return `через ${remind} мин`;
  if (remind < 1440) return remind % 60 ? `через ${Math.floor(remind / 60)} ч ${remind % 60} мин` : `через ${remind / 60} ч`;
  return "завтра";
}

async function run(env) {
  const users = await pushDocs(env);
  let sent = 0, checked = 0, errors = [];
  for (const u of users) {
    const subs = Array.isArray(u.subs) ? u.subs.filter(s => s && s.endpoint && s.keys) : [];
    if (!subs.length) continue;
    const now = localNow(u.tz), nowMs = now.getTime();
    const mon = mondayOf(now), next = new Date(mon.getTime() + 7 * 864e5);
    const sentDoc = (await getDoc(env, `users/${u.uid}/meta/sent`)) || {};
    const log = sentDoc.keys || {};
    const due = [];
    for (const wk of [mon, next]) {
      const w = await getDoc(env, `users/${u.uid}/weeks/${isoDay(wk)}`);
      for (const e of (w && w.events) || []) {
        if (e.remind == null || e.remind === "" || e.done) continue;
        checked++;
        const day = new Date(wk.getTime() + e.day * 864e5);
        const allDay = !e.start;
        const startMs = day.getTime() + (allDay ? 9 * 60 : toMin(e.start)) * 60000;
        const fireMs = startMs - (allDay ? (e.remind >= 1440 ? 1440 : 0) : Number(e.remind)) * 60000;
        const key = `${e.id}|${isoDay(day)}|${e.start || "-"}|${e.remind}`;
        if (fireMs <= nowMs && fireMs > nowMs - 15 * 60000 && !log[key]) due.push({ e, key, allDay });
      }
    }
    if (!due.length) continue;
    const dead = new Set();
    for (const { e, key, allDay } of due) {
      const time = allDay ? "" : ` · ${e.start}${e.end ? "–" + e.end : ""}`;
      const data = { title: e.title, body: `${whenText(Number(e.remind), allDay)}${time}`, tag: key };
      for (const s of subs) {
        try {
          const st = await sendPush(env, s, data);
          if (st === 404 || st === 410) dead.add(s.endpoint);
          else if (st >= 300) errors.push(`push ${st}`);
          else sent++;
        } catch (err) { errors.push(String(err.message || err).slice(0, 120)); }
      }
      log[key] = Date.now();
    }
    // keep two days of history
    for (const k in log) if (log[k] < Date.now() - 2 * 864e5) delete log[k];
    await setDoc(env, `users/${u.uid}/meta/sent`, { keys: log });
    if (dead.size) await setDoc(env, `users/${u.uid}/meta/push`, { subs: subs.filter(s => !dead.has(s.endpoint)), tz: u.tz || "UTC" });
  }
  await writeStatus(env, { ok: errors.length === 0, users: users.length, checked, sent, errors: errors.slice(0, 5) });
}

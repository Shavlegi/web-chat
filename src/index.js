/* web-chat — მარტივი ვებ-ჩატი ადმინ პანელით.
 *
 * Cloudflare Worker + D1. Auth/session პატერნები locallink-stock-ის
 * (~ /workspace/locallink-stock/src/index.js) და Mini Link-ის მიხედვით:
 * PBKDF2-SHA256 პაროლის hash თითო მომხმარებელზე ცალკე მარილით,
 * ბაზაში შენახული სესიები pepper-იანი ტოკენის hash-ით, IP-hash
 * rate limiting. ნედლი IP არსად ინახება.
 *
 * სპეციფიკაცია (შაოს სიტყვები): მომხმარებლები რეგისტრირდებიან და
 * შედიან მხოლოდ username-ით და პაროლით, მეტი არაფერი; ერთმანეთს
 * username-ით პოულობენ; 1:1 და ჯგუფური ჩატები, თითოეულ ჩატს თავისი
 * სათაური აქვს; ადმინ პანელში ყველა ჩატი თავის სათაურით ჩანს
 * (წევრებით და შეტყობინებების რაოდენობით, შიგნით შესვლაც შეიძლება)
 * და ყველა მომხმარებლის სიაა; მეტი არაფერი. პირველი დარეგისტრირებული
 * მომხმარებელი ავტომატურად ადმინი ხდება.
 *
 * საიდუმლოებები მხოლოდ env-ში: SESSION_SECRET.
 * არასდროს hardcode, არასდროს log.
 *
 * ინტერფეისი ერთი თვითკმარი HTML გვერდია ქვემოთ — გარე ფაილები არაა,
 * ამიტომ სტატიკური ფაილების სია არ სჭირდება. მუქი თემა, ქართული.
 */

const CONFIG = {
  sessionDays: 30,
  pbkdf2Iterations: 100000,
  registerLimitPerMin: 5,
  loginLimitPerMin: 5,
  messageLimitPerMin: 60,
  searchLimitPerMin: 60,
  maxMessageLen: 2000,
  maxTitleLen: 60,
  maxGroupMembers: 49,
};

const SESSION_COOKIE = 'chat_session';

/* ------------------------------------------------------------------ */
/* პატარა დამხმარეები                                                  */
/* ------------------------------------------------------------------ */

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'",
      ...SECURITY_HEADERS,
      ...extraHeaders,
    },
  });
}

function error(message, status = 400, extraHeaders = {}) {
  return json({ error: message }, status, extraHeaders);
}

function textEncoder() {
  return new TextEncoder();
}

function bytesToBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function base64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Constant-time შედარება (timing-ით ვერ გაიგებ, სად დაემთხვა).
function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function randomTokenHex(bytes = 32) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  const m = header.match(new RegExp('(?:^|;\\s*)' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]+)'));
  if (!m) return null;
  try {
    return decodeURIComponent(m[1]);
  } catch {
    return null;
  }
}

function sessionCookie(token, expiresAt, secure) {
  const parts = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${Math.floor((expiresAt - Date.now()) / 1000)}`,
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

function clearSessionCookie(secure) {
  const parts = [
    `${SESSION_COOKIE}=`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    'Max-Age=0',
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

function isHttps(request) {
  try {
    return new URL(request.url).protocol === 'https:';
  } catch {
    return false;
  }
}

// მუტაციური API-ები ბრაუზერიდან მხოლოდ ამ საიტიდან უნდა მოდიოდეს
// (SameSite=Lax უკვე ბლოკავს cross-site cookie-ებს; ეს მეორე ფენაა).
function originAllowed(request) {
  const origin = request.headers.get('Origin');
  if (!origin) return true; // არა-ბრაუზერის კლიენტი (curl და ა.შ.)
  try {
    return new URL(origin).host === new URL(request.url).host;
  } catch {
    return false;
  }
}

function cleanText(v, maxLen) {
  if (typeof v !== 'string') return '';
  const t = v.trim().replace(/\s+/g, ' ');
  return t.slice(0, maxLen);
}

// Username: მხოლოდ ლათინური ასოები, ციფრები და _, 3–30 სიმბოლო.
// პატარა ასოებად ინახება — „Nika" და „nika" ერთი და იგივეა.
function normalizeUsername(v) {
  if (typeof v !== 'string') return null;
  const u = v.trim().toLowerCase();
  if (!/^[a-z0-9_]{3,30}$/.test(u)) return null;
  return u;
}

/* ------------------------------------------------------------------ */
/* სქემა (lazy, idempotent — locallink-stock-ის ensureV* პატერნი)      */
/* ------------------------------------------------------------------ */

let schemaChecked = false;

async function ensureSchema(env) {
  if (schemaChecked) return;
  // v1: მომხმარებლები + სესიები + rate limit-ები.
  let v1done = false;
  try {
    const flag = await env.CHAT_DB.prepare(
      "SELECT value FROM schema_meta WHERE key = 'v1_users'",
    ).first();
    v1done = !!(flag && flag.value === '1');
  } catch (e) {
    // schema_meta (ან ნიშანი) ჯერ არ არსებობს — ქვემოთ მიგრაცია.
  }
  if (!v1done) {
    try {
      await env.CHAT_DB.batch([
        env.CHAT_DB.prepare(
          'CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
        ),
        env.CHAT_DB.prepare(
          'CREATE TABLE IF NOT EXISTS users (' +
          'id INTEGER PRIMARY KEY AUTOINCREMENT, ' +
          'username TEXT NOT NULL UNIQUE, ' +
          'password_hash TEXT NOT NULL, ' +
          'is_admin INTEGER NOT NULL DEFAULT 0, ' +
          'created_at INTEGER NOT NULL)',
        ),
        env.CHAT_DB.prepare(
          'CREATE TABLE IF NOT EXISTS sessions (' +
          'token_hash TEXT PRIMARY KEY, ' +
          'user_id INTEGER NOT NULL, ' +
          'created_at INTEGER NOT NULL, ' +
          'expires_at INTEGER NOT NULL)',
        ),
        env.CHAT_DB.prepare(
          'CREATE TABLE IF NOT EXISTS rate_limits (' +
          'key TEXT PRIMARY KEY, ' +
          'count INTEGER NOT NULL, ' +
          'window_start INTEGER NOT NULL)',
        ),
        env.CHAT_DB.prepare(
          "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('v1_users', '1')",
        ),
      ]);
    } catch (e) {
      console.error('ensureSchema v1 error:', e && e.message ? e.message : e);
      throw e;
    }
  }
  // v2: ჩატები + წევრები.
  try {
    const flag2 = await env.CHAT_DB.prepare(
      "SELECT value FROM schema_meta WHERE key = 'v2_chats'",
    ).first();
    if (!flag2 || flag2.value !== '1') {
      await env.CHAT_DB.batch([
        env.CHAT_DB.prepare(
          'CREATE TABLE IF NOT EXISTS chats (' +
          'id INTEGER PRIMARY KEY AUTOINCREMENT, ' +
          'title TEXT, ' +
          'is_group INTEGER NOT NULL DEFAULT 0, ' +
          'created_by INTEGER NOT NULL, ' +
          'created_at INTEGER NOT NULL)',
        ),
        env.CHAT_DB.prepare(
          'CREATE TABLE IF NOT EXISTS chat_members (' +
          'chat_id INTEGER NOT NULL, ' +
          'user_id INTEGER NOT NULL, ' +
          'last_read_at INTEGER NOT NULL DEFAULT 0, ' +
          'joined_at INTEGER NOT NULL, ' +
          'PRIMARY KEY (chat_id, user_id))',
        ),
        env.CHAT_DB.prepare(
          "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('v2_chats', '1')",
        ),
      ]);
    }
  } catch (e) {
    console.error('ensureSchema v2 error:', e && e.message ? e.message : e);
    throw e;
  }
  // v3: შეტყობინებები + ინდექსები.
  try {
    const flag3 = await env.CHAT_DB.prepare(
      "SELECT value FROM schema_meta WHERE key = 'v3_messages'",
    ).first();
    if (!flag3 || flag3.value !== '1') {
      await env.CHAT_DB.batch([
        env.CHAT_DB.prepare(
          'CREATE TABLE IF NOT EXISTS messages (' +
          'id INTEGER PRIMARY KEY AUTOINCREMENT, ' +
          'chat_id INTEGER NOT NULL, ' +
          'user_id INTEGER NOT NULL, ' +
          'body TEXT NOT NULL, ' +
          'created_at INTEGER NOT NULL)',
        ),
        env.CHAT_DB.prepare(
          'CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages (chat_id, id)',
        ),
        env.CHAT_DB.prepare(
          'CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members (user_id)',
        ),
        env.CHAT_DB.prepare(
          'CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id)',
        ),
        env.CHAT_DB.prepare(
          "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('v3_messages', '1')",
        ),
      ]);
    }
  } catch (e) {
    console.error('ensureSchema v3 error:', e && e.message ? e.message : e);
    throw e;
  }
  schemaChecked = true;
}

/* ------------------------------------------------------------------ */
/* პაროლი + სესიები (PBKDF2-SHA256 WebCrypto-თი)                       */
/* ------------------------------------------------------------------ */

// შენახვის ფორმატი: pbkdf2$<იტერაციები>$<მარილი base64>$<hash base64>
// მარილი თითო მომხმარებელზე ცალკე, შემთხვევითი 16 ბაიტი.
async function hashPassword(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const key = await crypto.subtle.importKey('raw', textEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: CONFIG.pbkdf2Iterations, hash: 'SHA-256' },
    key,
    256,
  );
  return 'pbkdf2$' + CONFIG.pbkdf2Iterations + '$' + bytesToBase64(salt) + '$' + bytesToBase64(new Uint8Array(bits));
}

async function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iterations = parseInt(parts[1], 10);
  if (!Number.isFinite(iterations) || iterations < 1000 || iterations > 1000000) return false;
  let salt;
  try {
    salt = base64ToBytes(parts[2]);
  } catch {
    return false;
  }
  const key = await crypto.subtle.importKey('raw', textEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    key,
    256,
  );
  return constantTimeEqual(bytesToBase64(new Uint8Array(bits)), parts[3]);
}

async function createSession(env, userId) {
  const token = randomTokenHex(32);
  const tokenHash = await sha256Hex((env.SESSION_SECRET || '') + ':' + token);
  const now = Date.now();
  const expiresAt = now + CONFIG.sessionDays * 24 * 60 * 60 * 1000;
  await env.CHAT_DB.prepare(
    'INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
  ).bind(tokenHash, userId, now, expiresAt).run();
  return { token, expiresAt };
}

// აბრუნებს შესული მომხმარებლის ჩანაწერს ან null-ს.
async function getSessionUser(env, request) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token || token.length < 32) return null;
  const tokenHash = await sha256Hex((env.SESSION_SECRET || '') + ':' + token);
  const row = await env.CHAT_DB.prepare(
    'SELECT s.user_id, s.expires_at, u.username, u.is_admin FROM sessions s ' +
    'JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?',
  ).bind(tokenHash).first();
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    await env.CHAT_DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run().catch(() => {});
    return null;
  }
  return { id: row.user_id, username: row.username, is_admin: row.is_admin === 1 };
}

async function destroySession(env, request) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return;
  const tokenHash = await sha256Hex((env.SESSION_SECRET || '') + ':' + token);
  await env.CHAT_DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run().catch(() => {});
}

/* ------------------------------------------------------------------ */
/* Rate limiting (IP hash-ით — ნედლი IP არსად ინახება)                 */
/* ------------------------------------------------------------------ */

async function ipHash(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const day = new Date().toISOString().slice(0, 10); // მარილი ყოველდღე იცვლება
  return sha256Hex(ip + '|' + day + '|' + (env.RATE_LIMIT_SALT || 'web-chat-default-salt'));
}

async function rateLimit(env, key, limit, windowSec) {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = Math.floor(now / windowSec) * windowSec;
  const dbKey = `${key}:${windowStart}`;
  try {
    await env.CHAT_DB.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(now - 86400).run();
    await env.CHAT_DB.prepare(
      'INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?) ' +
      'ON CONFLICT(key) DO UPDATE SET count = count + 1',
    ).bind(dbKey, windowStart).run();
    const row = await env.CHAT_DB.prepare('SELECT count FROM rate_limits WHERE key = ?').bind(dbKey).first();
    return (row ? row.count : 1) <= limit;
  } catch (e) {
    // Rate limiting რომ გაფუჭდეს, fail OPEN — ხელმისაწვდომობა პირველია.
    console.error('rateLimit error:', e && e.message ? e.message : e);
    return true;
  }
}

async function checkRateLimit(request, env, scope, limit, windowSec) {
  const hash = await ipHash(request, env);
  return rateLimit(env, `${scope}:${hash}`, limit, windowSec);
}

/* ------------------------------------------------------------------ */
/* მომხმარებლები / ჩატები — საერთო დამხმარეები                         */
/* ------------------------------------------------------------------ */

async function loadUserByUsername(env, username) {
  return env.CHAT_DB.prepare(
    'SELECT id, username, password_hash, is_admin, created_at FROM users WHERE username = ?',
  ).bind(username).first();
}

async function loadUserById(env, id) {
  return env.CHAT_DB.prepare(
    'SELECT id, username, is_admin, created_at FROM users WHERE id = ?',
  ).bind(id).first();
}

async function isMember(env, chatId, userId) {
  const row = await env.CHAT_DB.prepare(
    'SELECT 1 AS x FROM chat_members WHERE chat_id = ? AND user_id = ?',
  ).bind(chatId, userId).first();
  return !!row;
}

async function chatMemberUsernames(env, chatId) {
  const { results } = await env.CHAT_DB.prepare(
    'SELECT u.username FROM chat_members cm JOIN users u ON u.id = cm.user_id ' +
    'WHERE cm.chat_id = ? ORDER BY u.username',
  ).bind(chatId).all();
  return (results || []).map((r) => r.username);
}

// ჩატის საჩვენებელი სათაური კონკრეტული მომხმარებლისთვის:
// ჯგუფურს — შენახული სათაური; 1:1-ს — მეორე წევრის username.
async function displayTitle(env, chat, viewerId) {
  if (chat.is_group === 1) return chat.title || 'ჯგუფი';
  const { results } = await env.CHAT_DB.prepare(
    'SELECT u.username FROM chat_members cm JOIN users u ON u.id = cm.user_id ' +
    'WHERE cm.chat_id = ? AND cm.user_id != ? LIMIT 1',
  ).bind(chat.id, viewerId).all();
  return (results && results[0]) ? results[0].username : 'ჩატი';
}

function sessionCookieHeader(token, expiresAt, request) {
  return { 'Set-Cookie': sessionCookie(token, expiresAt, isHttps(request)) };
}

/* ------------------------------------------------------------------ */
/* Handlers — ავტორიზაცია                                              */
/* ------------------------------------------------------------------ */

async function handleRegister(env, request) {
  if (!originAllowed(request)) return error('არასწორი წყარო (Origin).', 403);
  const allowed = await checkRateLimit(request, env, 'register', CONFIG.registerLimitPerMin, 60);
  if (!allowed) return error('ძალიან ბევრი მცდელობა — ცოტა ხანში სცადეთ.', 429);
  let body;
  try {
    body = await request.json();
  } catch {
    return error('არასწორი მონაცემები.', 400);
  }
  const username = normalizeUsername(body && body.username);
  if (!username) {
    return error('Username: 3–30 სიმბოლო, მხოლოდ ლათინური ასოები, ციფრები და _.', 400);
  }
  const password = body && typeof body.password === 'string' ? body.password : '';
  if (password.length < 4 || password.length > 100) {
    return error('პაროლი: მინიმუმ 4 სიმბოლო.', 400);
  }
  const existing = await loadUserByUsername(env, username);
  if (existing) return error('ეს username უკვე დაკავებულია.', 400);
  // პირველი დარეგისტრირებული მომხმარებელი ავტომატურად ადმინი ხდება.
  const countRow = await env.CHAT_DB.prepare('SELECT COUNT(*) AS n FROM users').first();
  const isAdmin = !countRow || countRow.n === 0;
  const hash = await hashPassword(password);
  const res = await env.CHAT_DB.prepare(
    'INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)',
  ).bind(username, hash, isAdmin ? 1 : 0, Date.now()).run();
  const userId = res && res.meta ? res.meta.last_row_id : null;
  const { token, expiresAt } = await createSession(env, userId);
  return json({ ok: true, username, is_admin: isAdmin }, 200, sessionCookieHeader(token, expiresAt, request));
}

async function handleLogin(env, request) {
  if (!originAllowed(request)) return error('არასწორი წყარო (Origin).', 403);
  const allowed = await checkRateLimit(request, env, 'login', CONFIG.loginLimitPerMin, 60);
  if (!allowed) return error('ძალიან ბევრი მცდელობა — ცოტა ხანში სცადეთ.', 429);
  let body;
  try {
    body = await request.json();
  } catch {
    return error('არასწორი მონაცემები.', 400);
  }
  const username = normalizeUsername(body && body.username);
  const password = body && typeof body.password === 'string' ? body.password : '';
  // არასწორი username თუ პაროლი — ერთი და იგივე ზოგადი პასუხი:
  // პასუხმა არ უნდა გამოავლინოს, username არსებობს თუ არა.
  const user = username ? await loadUserByUsername(env, username) : null;
  const ok = user ? await verifyPassword(password, user.password_hash) : false;
  if (!ok) return error('არასწორი username ან პაროლი.', 401);
  const { token, expiresAt } = await createSession(env, user.id);
  return json({ ok: true, username: user.username, is_admin: user.is_admin === 1 }, 200, sessionCookieHeader(token, expiresAt, request));
}

async function handleLogout(env, request) {
  if (!originAllowed(request)) return error('არასწორი წყარო (Origin).', 403);
  await destroySession(env, request);
  return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie(isHttps(request)) });
}

async function handleMe(env, request) {
  const user = await getSessionUser(env, request);
  if (!user) return error('შესვლა საჭიროა.', 401);
  return json({ ok: true, username: user.username, is_admin: user.is_admin });
}

/* ------------------------------------------------------------------ */
/* Handlers — მომხმარებლების ძებნა                                     */
/* ------------------------------------------------------------------ */

async function handleUserSearch(env, request) {
  const user = await getSessionUser(env, request);
  if (!user) return error('შესვლა საჭიროა.', 401);
  const allowed = await checkRateLimit(request, env, 'search', CONFIG.searchLimitPerMin, 60);
  if (!allowed) return error('ძალიან ბევრი მოთხოვნა — ცოტა ხანში სცადეთ.', 429);
  const q = cleanText(new URL(request.url).searchParams.get('q') || '', 30).toLowerCase();
  if (q.length < 1) return json({ users: [] });
  const { results } = await env.CHAT_DB.prepare(
    'SELECT username FROM users WHERE username LIKE ? AND id != ? ORDER BY username LIMIT 20',
  ).bind(q + '%', user.id).all();
  return json({ users: (results || []).map((r) => r.username) });
}

/* ------------------------------------------------------------------ */
/* Handlers — ჩატები                                                   */
/* ------------------------------------------------------------------ */

async function handleCreateChat(env, request) {
  if (!originAllowed(request)) return error('არასწორი წყარო (Origin).', 403);
  const user = await getSessionUser(env, request);
  if (!user) return error('შესვლა საჭიროა.', 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return error('არასწორი მონაცემები.', 400);
  }
  const type = body && body.type;
  if (type === 'direct') {
    const peerName = normalizeUsername(body && body.username);
    if (!peerName) return error('მიუთითეთ მომხმარებლის username.', 400);
    if (peerName === user.username) return error('საკუთარ თავთან ჩატი არ შეიძლება.', 400);
    const peer = await loadUserByUsername(env, peerName);
    if (!peer) return error('ასეთი მომხმარებელი ვერ მოიძებნა.', 404);
    // არსებული 1:1 ჩატი უკვე თუ არის — იმას ვაბრუნებთ, დუბლიკატი არა.
    const existing = await env.CHAT_DB.prepare(
      'SELECT c.id FROM chats c ' +
      'JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = ? ' +
      'JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = ? ' +
      'WHERE c.is_group = 0 LIMIT 1',
    ).bind(user.id, peer.id).first();
    if (existing) return json({ ok: true, chat_id: existing.id, title: peer.username, is_group: false });
    const now = Date.now();
    const res = await env.CHAT_DB.prepare(
      'INSERT INTO chats (title, is_group, created_by, created_at) VALUES (NULL, 0, ?, ?)',
    ).bind(user.id, now).run();
    const chatId = res && res.meta ? res.meta.last_row_id : null;
    await env.CHAT_DB.batch([
      env.CHAT_DB.prepare(
        'INSERT INTO chat_members (chat_id, user_id, last_read_at, joined_at) VALUES (?, ?, 0, ?)',
      ).bind(chatId, user.id, now),
      env.CHAT_DB.prepare(
        'INSERT INTO chat_members (chat_id, user_id, last_read_at, joined_at) VALUES (?, ?, 0, ?)',
      ).bind(chatId, peer.id, now),
    ]);
    return json({ ok: true, chat_id: chatId, title: peer.username, is_group: false });
  }
  if (type === 'group') {
    const title = cleanText(body && body.title, CONFIG.maxTitleLen);
    if (!title) return error('ჯგუფის სათაური აუცილებელია.', 400);
    if (!Array.isArray(body.members) || body.members.length < 1 || body.members.length > CONFIG.maxGroupMembers) {
      return error('აირჩიეთ 1–49 წევრი.', 400);
    }
    const names = new Set();
    for (const raw of body.members) {
      const n = normalizeUsername(raw);
      if (!n || n === user.username) return error('წევრების სია არასწორია.', 400);
      names.add(n);
    }
    const memberRows = [];
    for (const name of names) {
      const row = await loadUserByUsername(env, name);
      if (!row) return error('მომხმარებელი ვერ მოიძებნა: ' + name, 404);
      memberRows.push(row);
    }
    const now = Date.now();
    const res = await env.CHAT_DB.prepare(
      'INSERT INTO chats (title, is_group, created_by, created_at) VALUES (?, 1, ?, ?)',
    ).bind(title, user.id, now).run();
    const chatId = res && res.meta ? res.meta.last_row_id : null;
    const stmts = [
      env.CHAT_DB.prepare(
        'INSERT INTO chat_members (chat_id, user_id, last_read_at, joined_at) VALUES (?, ?, 0, ?)',
      ).bind(chatId, user.id, now),
    ];
    for (const m of memberRows) {
      stmts.push(env.CHAT_DB.prepare(
        'INSERT INTO chat_members (chat_id, user_id, last_read_at, joined_at) VALUES (?, ?, 0, ?)',
      ).bind(chatId, m.id, now));
    }
    await env.CHAT_DB.batch(stmts);
    return json({ ok: true, chat_id: chatId, title, is_group: true });
  }
  return error('ჩატის ტიპი არასწორია.', 400);
}

async function handleListChats(env, request) {
  const user = await getSessionUser(env, request);
  if (!user) return error('შესვლა საჭიროა.', 401);
  const { results } = await env.CHAT_DB.prepare(
    'SELECT c.id, c.title, c.is_group, c.created_at, cm.last_read_at FROM chats c ' +
    'JOIN chat_members cm ON cm.chat_id = c.id AND cm.user_id = ? ' +
    'ORDER BY c.created_at DESC',
  ).bind(user.id).all();
  const chats = [];
  for (const c of results || []) {
    const last = await env.CHAT_DB.prepare(
      'SELECT m.body, m.created_at, u.username FROM messages m ' +
      'JOIN users u ON u.id = m.user_id WHERE m.chat_id = ? ORDER BY m.id DESC LIMIT 1',
    ).bind(c.id).first();
    const unreadRow = await env.CHAT_DB.prepare(
      'SELECT COUNT(*) AS n FROM messages WHERE chat_id = ? AND created_at > ? AND user_id != ?',
    ).bind(c.id, c.last_read_at, user.id).first();
    chats.push({
      id: c.id,
      title: await displayTitle(env, c, user.id),
      is_group: c.is_group === 1,
      members: await chatMemberUsernames(env, c.id),
      last_message: last ? last.body : null,
      last_username: last ? last.username : null,
      last_at: last ? last.created_at : c.created_at,
      unread: unreadRow ? unreadRow.n : 0,
    });
  }
  // უახლესი შეტყობინების მიხედვით დალაგება (ცარიელი ჩატები — შექმნის დროით).
  chats.sort((a, b) => b.last_at - a.last_at);
  return json({ chats });
}

async function handleGetMessages(env, request, chatId) {
  const user = await getSessionUser(env, request);
  if (!user) return error('შესვლა საჭიროა.', 401);
  const chat = await env.CHAT_DB.prepare('SELECT id, title, is_group FROM chats WHERE id = ?').bind(chatId).first();
  if (!chat) return error('ჩატი ვერ მოიძებნა.', 404);
  if (!(await isMember(env, chatId, user.id))) return error('ამ ჩატის წევრი არ ხარ.', 403);
  const params = new URL(request.url).searchParams;
  const after = parseInt(params.get('after') || '0', 10);
  let rows;
  if (Number.isInteger(after) && after > 0) {
    const r = await env.CHAT_DB.prepare(
      'SELECT m.id, m.body, m.created_at, u.username FROM messages m ' +
      'JOIN users u ON u.id = m.user_id WHERE m.chat_id = ? AND m.id > ? ORDER BY m.id ASC LIMIT 100',
    ).bind(chatId, after).all();
    rows = r.results || [];
  } else {
    const r = await env.CHAT_DB.prepare(
      'SELECT m.id, m.body, m.created_at, u.username FROM messages m ' +
      'JOIN users u ON u.id = m.user_id WHERE m.chat_id = ? ORDER BY m.id DESC LIMIT 50',
    ).bind(chatId).all();
    rows = (r.results || []).reverse();
  }
  // წაკითხულად მონიშვნა.
  await env.CHAT_DB.prepare(
    'UPDATE chat_members SET last_read_at = ? WHERE chat_id = ? AND user_id = ?',
  ).bind(Date.now(), chatId, user.id).run();
  return json({
    chat: {
      id: chat.id,
      title: await displayTitle(env, chat, user.id),
      is_group: chat.is_group === 1,
      members: await chatMemberUsernames(env, chatId),
    },
    messages: rows.map((m) => ({ id: m.id, username: m.username, body: m.body, created_at: m.created_at, mine: m.username === user.username })),
  });
}

async function handleSendMessage(env, request, chatId) {
  if (!originAllowed(request)) return error('არასწორი წყარო (Origin).', 403);
  const user = await getSessionUser(env, request);
  if (!user) return error('შესვლა საჭიროა.', 401);
  const allowed = await checkRateLimit(request, env, 'message', CONFIG.messageLimitPerMin, 60);
  if (!allowed) return error('ძალიან ბევრი შეტყობინება — ცოტა ხანში სცადეთ.', 429);
  const chat = await env.CHAT_DB.prepare('SELECT id FROM chats WHERE id = ?').bind(chatId).first();
  if (!chat) return error('ჩატი ვერ მოიძებნა.', 404);
  if (!(await isMember(env, chatId, user.id))) return error('ამ ჩატის წევრი არ ხარ.', 403);
  let body;
  try {
    body = await request.json();
  } catch {
    return error('არასწორი მონაცემები.', 400);
  }
  const text = typeof body.body === 'string' ? body.body.trim() : '';
  if (!text || text.length > CONFIG.maxMessageLen) {
    return error('შეტყობინება: 1–2000 სიმბოლო.', 400);
  }
  const res = await env.CHAT_DB.prepare(
    'INSERT INTO messages (chat_id, user_id, body, created_at) VALUES (?, ?, ?, ?)',
  ).bind(chatId, user.id, text, Date.now()).run();
  const id = res && res.meta ? res.meta.last_row_id : null;
  await env.CHAT_DB.prepare(
    'UPDATE chat_members SET last_read_at = ? WHERE chat_id = ? AND user_id = ?',
  ).bind(Date.now(), chatId, user.id).run();
  return json({ ok: true, id, body: text, created_at: Date.now() });
}

/* ------------------------------------------------------------------ */
/* Handlers — ადმინი                                                   */
/* ------------------------------------------------------------------ */

async function requireAdmin(env, request) {
  const user = await getSessionUser(env, request);
  if (!user) return { error: error('შესვლა საჭიროა.', 401) };
  if (!user.is_admin) return { error: error('ადმინის უფლება საჭიროა.', 403) };
  return { user };
}

async function handleAdminOverview(env, request) {
  const auth = await requireAdmin(env, request);
  if (auth.error) return auth.error;
  const { results: chatRows } = await env.CHAT_DB.prepare(
    'SELECT c.id, c.title, c.is_group, c.created_at, COUNT(m.id) AS message_count ' +
    'FROM chats c LEFT JOIN messages m ON m.chat_id = c.id ' +
    'GROUP BY c.id ORDER BY c.created_at DESC',
  ).all();
  const chats = [];
  for (const c of chatRows || []) {
    chats.push({
      id: c.id,
      // 1:1 ჩატის სათაური ადმინისთვის = ორივე წევრის username.
      title: c.is_group === 1 ? c.title : (await chatMemberUsernames(env, c.id)).join(' ↔ '),
      is_group: c.is_group === 1,
      members: await chatMemberUsernames(env, c.id),
      message_count: c.message_count,
      created_at: c.created_at,
    });
  }
  const { results: userRows } = await env.CHAT_DB.prepare(
    'SELECT username, is_admin, created_at FROM users ORDER BY created_at ASC',
  ).all();
  return json({
    chats,
    users: (userRows || []).map((u) => ({
      username: u.username,
      is_admin: u.is_admin === 1,
      created_at: u.created_at,
    })),
  });
}

// ადმინი ნებისმიერ ჩატში შედის და მის შეტყობინებებს კითხულობს.
async function handleAdminChatMessages(env, request, chatId) {
  const auth = await requireAdmin(env, request);
  if (auth.error) return auth.error;
  const chat = await env.CHAT_DB.prepare('SELECT id, title, is_group FROM chats WHERE id = ?').bind(chatId).first();
  if (!chat) return error('ჩატი ვერ მოიძებნა.', 404);
  const { results } = await env.CHAT_DB.prepare(
    'SELECT m.id, m.body, m.created_at, u.username FROM messages m ' +
    'JOIN users u ON u.id = m.user_id WHERE m.chat_id = ? ORDER BY m.id DESC LIMIT 100',
  ).bind(chatId).all();
  return json({
    chat: {
      id: chat.id,
      title: chat.is_group === 1 ? chat.title : (await chatMemberUsernames(env, chatId)).join(' ↔ '),
      is_group: chat.is_group === 1,
      members: await chatMemberUsernames(env, chatId),
    },
    messages: (results || []).reverse().map((m) => ({
      id: m.id, username: m.username, body: m.body, created_at: m.created_at,
    })),
  });
}

/* ------------------------------------------------------------------ */
/* ჩატის გვერდი (ერთი თვითკმარი გვერდი, გარე ფაილები არაა)             */
/* შენიშვნა: ქვემოთ inline <script>-ში არ უნდა იყოს backtick ან ${ }   */
/* თანმიმდევრობა — ის JS template literal-ში ცხოვრობს.                  */
/* ------------------------------------------------------------------ */

function chatPage() {
  const html = `<!DOCTYPE html>
<html lang="ka">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ჩატი</title>
<style>
:root{--bg:#0A0D14;--surface:#17243B;--surface2:#1C2C48;--accent:#3978FF;--text:#F2F5FA;--muted:#9AA9C2;--border:rgba(255,255,255,.09);--mine:#1E5BFF}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;font-size:16px;line-height:1.5}
.container{max-width:960px;margin:0 auto;padding:16px}
h1{font-size:22px;margin:0}
.sub{color:var(--muted);font-size:14px;margin:6px 0 20px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:18px;margin-bottom:14px}
input[type=text],input[type=password]{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:10px;color:var(--text);padding:11px 13px;margin-bottom:10px;font-size:16px}
label.fl{display:block;font-weight:600;font-size:14px;margin-bottom:6px}
.btn{display:inline-flex;align-items:center;justify-content:center;background:var(--accent);color:#fff;border:1px solid var(--accent);border-radius:10px;padding:11px 20px;font-weight:700;font-size:15px;cursor:pointer}
.btn:disabled{opacity:.6;cursor:wait}
.btn-outline{background:transparent;border-color:rgba(255,255,255,.25);color:var(--text)}
.btn-block{width:100%}
.btn-sm{padding:7px 12px;font-size:14px}
.err{background:rgba(255,107,107,.12);border:1px solid rgba(255,107,107,.5);border-radius:10px;padding:11px 13px;font-size:14px;font-weight:600;margin-bottom:14px}
.err[hidden]{display:none}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:14px}
.topbar .who{color:var(--muted);font-size:14px}
.layout{display:grid;grid-template-columns:300px 1fr;gap:14px}
@media(max-width:720px){.layout{grid-template-columns:1fr}}
.side .search-row{display:flex;gap:8px}
.side .search-row input{margin-bottom:0}
.chat-item{display:block;width:100%;text-align:left;background:var(--surface);border:1px solid var(--border);border-radius:12px;color:var(--text);padding:12px 14px;margin-bottom:8px;cursor:pointer}
.chat-item.on{border-color:var(--accent)}
.chat-item .t{font-weight:700;font-size:15px}
.chat-item .m{color:var(--muted);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.badge{display:inline-block;background:#E5484D;color:#fff;border-radius:999px;font-size:12px;font-weight:700;padding:1px 8px;margin-left:6px}
.conv{display:flex;flex-direction:column;height:70vh;min-height:420px}
.conv-head{border-bottom:1px solid var(--border);padding-bottom:10px;margin-bottom:10px}
.conv-head .t{font-weight:700;font-size:17px}
.conv-head .m{color:var(--muted);font-size:13px}
.msgs{flex:1;overflow-y:auto;padding-right:4px}
.msg{max-width:75%;padding:9px 12px;border-radius:14px;margin-bottom:8px;background:var(--surface2);word-break:break-word}
.msg.mine{margin-left:auto;background:var(--mine)}
.msg .u{font-size:12px;color:var(--muted);font-weight:700}
.msg.mine .u{color:rgba(255,255,255,.75)}
.msg .time{font-size:11px;color:var(--muted);margin-top:2px}
.send-row{display:flex;gap:8px;margin-top:10px}
.send-row input{margin-bottom:0}
.admin-row{display:flex;justify-content:space-between;gap:10px;align-items:center;padding:10px 0;border-top:1px solid var(--border);font-size:14px}
.admin-row:first-child{border-top:0}
.admin-row .t{font-weight:700}
.admin-row .m{color:var(--muted);font-size:13px}
.tabs{display:flex;gap:8px;margin-bottom:14px}
.tab-btn{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:999px;padding:8px 16px;cursor:pointer;font-size:14px;font-weight:700}
.tab-btn.on{background:var(--accent);border-color:var(--accent)}
.hint{color:var(--muted);font-size:13px}
[hidden]{display:none!important}
</style>
</head>
<body>
<div class="container">
  <div id="auth-view">
    <h1>ჩატი</h1>
    <p class="sub">მხოლოდ username და პაროლი — მეტი არაფერი.</p>
    <div class="card" style="max-width:420px">
      <div class="tabs">
        <button class="tab-btn on" id="tab-login" type="button">შესვლა</button>
        <button class="tab-btn" id="tab-register" type="button">რეგისტრაცია</button>
      </div>
      <div class="err" id="auth-err" hidden></div>
      <label class="fl" for="auth-username">Username</label>
      <input type="text" id="auth-username" autocomplete="username" placeholder="მაგ. shao">
      <label class="fl" for="auth-password">პაროლი</label>
      <input type="password" id="auth-password" autocomplete="current-password" placeholder="მინიმუმ 4 სიმბოლო">
      <button class="btn btn-block" id="auth-submit" type="button">შესვლა</button>
      <p class="hint" id="auth-hint">Username: 3–30 სიმბოლო, მხოლოდ ლათინური ასოები, ციფრები და _.</p>
      <p class="hint" id="reg-hint" hidden>პირველი დარეგისტრირებული მომხმარებელი ავტომატურად ადმინი ხდება.</p>
    </div>
  </div>

  <div id="app-view" hidden>
    <div class="topbar">
      <h1>ჩატი</h1>
      <div>
        <span class="who" id="who-line"></span>
        <button class="btn btn-outline btn-sm" id="admin-btn" type="button" hidden>ადმინი</button>
        <button class="btn btn-outline btn-sm" id="logout-btn" type="button">გასვლა</button>
      </div>
    </div>
    <div class="layout">
      <div class="side">
        <div class="card">
          <label class="fl">მომხმარებლის ძებნა</label>
          <div class="search-row">
            <input type="text" id="search-input" placeholder="username...">
            <button class="btn btn-sm" id="search-btn" type="button">ძებნა</button>
          </div>
          <div id="search-results" style="margin-top:10px"></div>
        </div>
        <div class="card">
          <label class="fl">ახალი ჯგუფი</label>
          <input type="text" id="group-title" placeholder="ჯგუფის სათაური">
          <input type="text" id="group-members" placeholder="წევრები username-ებით, მძიმით">
          <button class="btn btn-block btn-sm" id="group-create" type="button">ჯგუფის შექმნა</button>
        </div>
        <div id="chat-list"></div>
      </div>
      <div class="card conv" id="conv-view">
        <div class="conv-head">
          <div class="t" id="conv-title">აირჩიე ჩატი</div>
          <div class="m" id="conv-members"></div>
        </div>
        <div class="msgs" id="msgs"></div>
        <div class="send-row" id="send-row" hidden>
          <input type="text" id="msg-input" placeholder="შეტყობინება..." maxlength="2000">
          <button class="btn" id="send-btn" type="button">გაგზავნა</button>
        </div>
      </div>
    </div>
  </div>

  <div id="admin-view" hidden>
    <div class="topbar">
      <h1>ადმინი</h1>
      <button class="btn btn-outline btn-sm" id="admin-back" type="button">← ჩატში დაბრუნება</button>
    </div>
    <div class="card">
      <h2 style="font-size:17px;margin:0 0 6px">ყველა ჩატი</h2>
      <div id="admin-chats"></div>
    </div>
    <div class="card">
      <h2 style="font-size:17px;margin:0 0 6px">ყველა მომხმარებელი</h2>
      <div id="admin-users"></div>
    </div>
    <div class="card" id="admin-chat-view" hidden>
      <h2 style="font-size:17px;margin:0 0 6px" id="admin-chat-title"></h2>
      <div id="admin-chat-msgs"></div>
    </div>
  </div>
</div>
<script>
(function () {
  var me = null;
  var chats = [];
  var currentChat = null;
  var lastMsgId = 0;
  var authMode = 'login';
  var pollTimer = null;

  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function fmtTime(ts) {
    var d = new Date(ts);
    var h = d.getHours();
    var m = d.getMinutes();
    return (h < 10 ? '0' + h : h) + ':' + (m < 10 ? '0' + m : m);
  }
  function showErr(el, msg) {
    el.textContent = msg;
    el.hidden = false;
  }
  function api(path, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    if (opts.body && typeof opts.body !== 'string') {
      opts.body = JSON.stringify(opts.body);
      opts.headers['Content-Type'] = 'application/json';
    }
    return fetch(path, opts).then(function (res) {
      return res.json().then(function (data) {
        if (!res.ok) throw new Error(data.error || ('შეცდომა ' + res.status));
        return data;
      });
    });
  }

  function setAuthMode(mode) {
    authMode = mode;
    document.getElementById('tab-login').className = 'tab-btn' + (mode === 'login' ? ' on' : '');
    document.getElementById('tab-register').className = 'tab-btn' + (mode === 'register' ? ' on' : '');
    document.getElementById('auth-submit').textContent = mode === 'login' ? 'შესვლა' : 'რეგისტრაცია';
    document.getElementById('reg-hint').hidden = mode !== 'register';
    document.getElementById('auth-err').hidden = true;
  }
  document.getElementById('tab-login').addEventListener('click', function () { setAuthMode('login'); });
  document.getElementById('tab-register').addEventListener('click', function () { setAuthMode('register'); });

  document.getElementById('auth-submit').addEventListener('click', function () {
    var username = document.getElementById('auth-username').value;
    var password = document.getElementById('auth-password').value;
    var errEl = document.getElementById('auth-err');
    errEl.hidden = true;
    var path = authMode === 'login' ? '/api/login' : '/api/register';
    api(path, { method: 'POST', body: { username: username, password: password } }).then(function (data) {
      me = { username: data.username, is_admin: !!data.is_admin };
      enterApp();
    }).catch(function (e) { showErr(errEl, e.message); });
  });
  document.getElementById('auth-password').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') document.getElementById('auth-submit').click();
  });

  function enterApp() {
    document.getElementById('auth-view').hidden = true;
    document.getElementById('admin-view').hidden = true;
    document.getElementById('app-view').hidden = false;
    document.getElementById('who-line').textContent = me.username + (me.is_admin ? ' (ადმინი)' : '');
    document.getElementById('admin-btn').hidden = !me.is_admin;
    refreshChats();
    pollTimer = setInterval(function () {
      refreshChats(true);
      if (currentChat) pollMessages();
    }, 5000);
  }

  document.getElementById('logout-btn').addEventListener('click', function () {
    api('/api/logout', { method: 'POST' }).catch(function () {});
    if (pollTimer) clearInterval(pollTimer);
    me = null; currentChat = null; chats = [];
    document.getElementById('app-view').hidden = true;
    document.getElementById('admin-view').hidden = true;
    document.getElementById('auth-view').hidden = false;
  });

  function renderChatList() {
    var list = document.getElementById('chat-list');
    var html = '';
    chats.forEach(function (c) {
      var badge = c.unread > 0 ? '<span class="badge">' + c.unread + '</span>' : '';
      var last = c.last_message ? esc(c.last_username + ': ' + c.last_message) : 'შეტყობინებები ჯერ არაა';
      html += '<button type="button" class="chat-item' + (currentChat && currentChat.id === c.id ? ' on' : '') + '" data-chat="' + c.id + '">' +
        '<div class="t">' + esc(c.title) + badge + '</div>' +
        '<div class="m">' + last + '</div></button>';
    });
    list.innerHTML = html || '<p class="hint">ჩატები ჯერ არაა — მოძებნე მომხმარებელი username-ით და დაიწყე.</p>';
    var btns = list.querySelectorAll('[data-chat]');
    btns.forEach(function (b) {
      b.addEventListener('click', function () { openChat(parseInt(b.getAttribute('data-chat'), 10)); });
    });
  }

  function refreshChats(quiet) {
    return api('/api/chats').then(function (data) {
      chats = data.chats;
      renderChatList();
    }).catch(function () { if (!quiet) {} });
  }

  function openChat(chatId) {
    currentChat = null; lastMsgId = 0;
    document.getElementById('msgs').innerHTML = '';
    api('/api/chats/' + chatId + '/messages').then(function (data) {
      currentChat = data.chat;
      document.getElementById('conv-title').textContent = data.chat.title;
      document.getElementById('conv-members').textContent = data.chat.members.join(', ');
      document.getElementById('send-row').hidden = false;
      renderMessages(data.messages, true);
      refreshChats(true);
    }).catch(function (e) { alert(e.message); });
  }

  function renderMessages(msgs, reset) {
    var box = document.getElementById('msgs');
    if (reset) box.innerHTML = '';
    msgs.forEach(function (m) {
      lastMsgId = Math.max(lastMsgId, m.id);
      var div = document.createElement('div');
      div.className = 'msg' + (m.mine ? ' mine' : '');
      div.innerHTML = '<div class="u">' + esc(m.username) + '</div><div>' + esc(m.body) + '</div><div class="time">' + fmtTime(m.created_at) + '</div>';
      box.appendChild(div);
    });
    box.scrollTop = box.scrollHeight;
  }

  function pollMessages() {
    if (!currentChat) return;
    api('/api/chats/' + currentChat.id + '/messages?after=' + lastMsgId).then(function (data) {
      if (data.messages.length) renderMessages(data.messages, false);
    }).catch(function () {});
  }

  function sendMessage() {
    var input = document.getElementById('msg-input');
    var text = input.value.trim();
    if (!text || !currentChat) return;
    input.value = '';
    api('/api/chats/' + currentChat.id + '/messages', { method: 'POST', body: { body: text } }).then(function () {
      pollMessages();
      refreshChats(true);
    }).catch(function (e) { alert(e.message); });
  }
  document.getElementById('send-btn').addEventListener('click', sendMessage);
  document.getElementById('msg-input').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') sendMessage();
  });

  document.getElementById('search-btn').addEventListener('click', function () {
    var q = document.getElementById('search-input').value.trim();
    var box = document.getElementById('search-results');
    if (!q) { box.innerHTML = ''; return; }
    api('/api/users/search?q=' + encodeURIComponent(q)).then(function (data) {
      if (!data.users.length) { box.innerHTML = '<p class="hint">ვერ მოიძებნა.</p>'; return; }
      var html = '';
      data.users.forEach(function (u) {
        html += '<div class="admin-row"><span class="t">' + esc(u) + '</span>' +
          '<button type="button" class="btn btn-sm" data-start="' + esc(u) + '">ჩატის დაწყება</button></div>';
      });
      box.innerHTML = html;
      box.querySelectorAll('[data-start]').forEach(function (b) {
        b.addEventListener('click', function () {
          api('/api/chats', { method: 'POST', body: { type: 'direct', username: b.getAttribute('data-start') } }).then(function (data) {
            box.innerHTML = '';
            document.getElementById('search-input').value = '';
            refreshChats().then(function () { openChat(data.chat_id); });
          }).catch(function (e) { alert(e.message); });
        });
      });
    }).catch(function (e) { alert(e.message); });
  });

  document.getElementById('group-create').addEventListener('click', function () {
    var title = document.getElementById('group-title').value.trim();
    var raw = document.getElementById('group-members').value;
    var members = raw.split(',').map(function (s) { return s.trim(); }).filter(function (s) { return s.length > 0; });
    api('/api/chats', { method: 'POST', body: { type: 'group', title: title, members: members } }).then(function (data) {
      document.getElementById('group-title').value = '';
      document.getElementById('group-members').value = '';
      refreshChats().then(function () { openChat(data.chat_id); });
    }).catch(function (e) { alert(e.message); });
  });

  document.getElementById('admin-btn').addEventListener('click', function () {
    document.getElementById('app-view').hidden = true;
    document.getElementById('admin-view').hidden = false;
    loadAdmin();
  });
  document.getElementById('admin-back').addEventListener('click', function () {
    document.getElementById('admin-view').hidden = true;
    document.getElementById('app-view').hidden = false;
    refreshChats();
  });

  function loadAdmin() {
    api('/api/admin/overview').then(function (data) {
      var chatsHtml = '';
      data.chats.forEach(function (c) {
        chatsHtml += '<div class="admin-row"><span><span class="t">' + esc(c.title) + '</span><br>' +
          '<span class="m">' + esc(c.members.join(', ')) + ' · შეტყობინებები: ' + c.message_count + '</span></span>' +
          '<button type="button" class="btn btn-sm" data-admin-chat="' + c.id + '">შესვლა</button></div>';
      });
      document.getElementById('admin-chats').innerHTML = chatsHtml || '<p class="hint">ჩატები ჯერ არაა.</p>';
      var usersHtml = '';
      data.users.forEach(function (u) {
        usersHtml += '<div class="admin-row"><span class="t">' + esc(u.username) + '</span>' +
          '<span class="m">' + (u.is_admin ? 'ადმინი' : 'მომხმარებელი') + '</span></div>';
      });
      document.getElementById('admin-users').innerHTML = usersHtml || '<p class="hint">მომხმარებლები ჯერ არაა.</p>';
      document.querySelectorAll('[data-admin-chat]').forEach(function (b) {
        b.addEventListener('click', function () {
          var id = parseInt(b.getAttribute('data-admin-chat'), 10);
          api('/api/admin/chats/' + id + '/messages').then(function (d) {
            document.getElementById('admin-chat-view').hidden = false;
            document.getElementById('admin-chat-title').textContent = d.chat.title + ' — ' + d.chat.members.join(', ');
            var html = '';
            d.messages.forEach(function (m) {
              html += '<div class="admin-row"><span><span class="t">' + esc(m.username) + '</span> ' + esc(m.body) + '</span><span class="m">' + fmtTime(m.created_at) + '</span></div>';
            });
            document.getElementById('admin-chat-msgs').innerHTML = html || '<p class="hint">შეტყობინებები ჯერ არაა.</p>';
          }).catch(function (e) { alert(e.message); });
        });
      });
    }).catch(function (e) { alert(e.message); });
  }

  // გვერდის ჩატვირთვისას — უკვე შესული ვართ?
  api('/api/me').then(function (data) {
    me = { username: data.username, is_admin: !!data.is_admin };
    enterApp();
  }).catch(function () {});
})();
</script>
</body>
</html>`;
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'",
      ...SECURITY_HEADERS,
    },
  });
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // HTTPS-ის იძულება production-ში; localhost გამონაკლისია, რომ
    // ლოკალური dev და ოფლაინ harness-ი http-ზეც იმუშაოს.
    if (url.protocol === 'http:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1' && url.hostname !== '[::1]') {
      return Response.redirect('https://' + url.host + url.pathname + url.search, 301);
    }

    try {
      await ensureSchema(env);
    } catch (e) {
      return error('მონაცემთა ბაზის შეცდომა.', 500);
    }

    if (path === '/' && request.method === 'GET') {
      return chatPage();
    }
    if (path === '/api/health' && request.method === 'GET') {
      return json({ ok: true, service: 'web-chat' });
    }

    if (path === '/api/register' && request.method === 'POST') {
      return handleRegister(env, request);
    }
    if (path === '/api/login' && request.method === 'POST') {
      return handleLogin(env, request);
    }
    if (path === '/api/logout' && request.method === 'POST') {
      return handleLogout(env, request);
    }
    if (path === '/api/me' && request.method === 'GET') {
      return handleMe(env, request);
    }
    if (path === '/api/users/search' && request.method === 'GET') {
      return handleUserSearch(env, request);
    }
    if (path === '/api/chats' && request.method === 'POST') {
      return handleCreateChat(env, request);
    }
    if (path === '/api/chats' && request.method === 'GET') {
      return handleListChats(env, request);
    }
    if (path.startsWith('/api/chats/') && path.endsWith('/messages') && request.method === 'GET') {
      const id = parseInt(path.slice('/api/chats/'.length, -'/messages'.length), 10);
      if (!Number.isInteger(id) || id < 1) return error('არასწორი ჩატი.', 400);
      return handleGetMessages(env, request, id);
    }
    if (path.startsWith('/api/chats/') && path.endsWith('/messages') && request.method === 'POST') {
      const id = parseInt(path.slice('/api/chats/'.length, -'/messages'.length), 10);
      if (!Number.isInteger(id) || id < 1) return error('არასწორი ჩატი.', 400);
      return handleSendMessage(env, request, id);
    }
    if (path === '/api/admin/overview' && request.method === 'GET') {
      return handleAdminOverview(env, request);
    }
    if (path.startsWith('/api/admin/chats/') && path.endsWith('/messages') && request.method === 'GET') {
      const id = parseInt(path.slice('/api/admin/chats/'.length, -'/messages'.length), 10);
      if (!Number.isInteger(id) || id < 1) return error('არასწორი ჩატი.', 400);
      return handleAdminChatMessages(env, request, id);
    }

    return error('ვერ მოიძებნა.', 404);
  },
};

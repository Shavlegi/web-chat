// Harness tests for the web-chat Worker (plain node, no deploy).
// D1Mock over node:sqlite; the Worker module is imported directly.
// Run: node test/chat-harness.mjs
// All secrets here are TEST-ONLY dummies — never use them in production.
import { DatabaseSync } from 'node:sqlite';
import worker from '../src/index.js';

const BASE = 'https://web-chat.shao42ia.workers.dev';
const SESSION_SECRET = 'harness-test-secret-do-not-use-in-production';

class D1Statement {
  constructor(db, sql) { this.db = db; this.sql = sql; this.params = []; }
  bind(...params) { this.params = params; return this; }
  async run() {
    const r = this.db.prepare(this.sql).run(...this.params);
    return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid) } };
  }
  async first() {
    const row = this.db.prepare(this.sql).get(...this.params);
    return row === undefined ? null : row;
  }
  async all() {
    return { results: this.db.prepare(this.sql).all(...this.params) };
  }
}

class D1Mock {
  constructor(db) { this.db = db; }
  prepare(sql) { return new D1Statement(this.db, sql); }
  async batch(statements) {
    const out = [];
    for (const s of statements) out.push(await s.run());
    return out;
  }
}

const db = new DatabaseSync(':memory:');
const env = {
  CHAT_DB: new D1Mock(db),
  SESSION_SECRET,
  RATE_LIMIT_SALT: 'harness-salt',
};

let passed = 0;
let failed = 0;
const failures = [];
function check(name, cond, extra) {
  if (cond) { passed++; console.log('  PASS ' + name); }
  else { failed++; failures.push(name); console.log('  FAIL ' + name + (extra ? ' — ' + extra : '')); }
}

async function req(method, path, { headers = {}, body = null, ip = '10.0.0.1' } = {}) {
  const init = { method, headers: { 'CF-Connecting-IP': ip, ...headers } };
  if (body !== null) init.body = typeof body === 'string' ? body : JSON.stringify(body);
  return worker.fetch(new Request(BASE + path, init), env);
}

async function reqFull(method, url, { headers = {}, body = null, ip = '10.0.0.1' } = {}) {
  const init = { method, headers: { 'CF-Connecting-IP': ip, ...headers } };
  if (body !== null) init.body = typeof body === 'string' ? body : JSON.stringify(body);
  return worker.fetch(new Request(url, init), env);
}

function cookieFrom(res) {
  const setCookie = res.headers.get('set-cookie') || '';
  const m = setCookie.match(/chat_session=[^;]+/);
  return m ? m[0] : null;
}

async function register(username, password, ip) {
  const res = await req('POST', '/api/register', { ip, headers: { 'Content-Type': 'application/json' }, body: { username, password } });
  return { res, data: await res.json().catch(() => ({})), cookie: cookieFrom(res) };
}

async function login(username, password, ip) {
  const res = await req('POST', '/api/login', { ip, headers: { 'Content-Type': 'application/json' }, body: { username, password } });
  return { res, data: await res.json().catch(() => ({})), cookie: cookieFrom(res) };
}

// ---------- https redirect + root page + health ----------
{
  const r1 = await reqFull('GET', 'http://web-chat.shao42ia.workers.dev/');
  check('http root redirects 301 to https', r1.status === 301 && r1.headers.get('location') === 'https://web-chat.shao42ia.workers.dev/', 'status=' + r1.status);
  const r2 = await reqFull('GET', 'http://localhost:8787/');
  check('http localhost exempt from redirect', r2.status === 200, 'status=' + r2.status);
  const page = await req('GET', '/');
  const html = await page.text();
  check('GET / returns chat HTML page', page.status === 200 && (page.headers.get('content-type') || '').includes('text/html'));
  check('chat page is Georgian', html.includes('ჩატი') && html.includes('რეგისტრაცია') && html.includes('შესვლა'));
  check('chat page mentions admin + username search', html.includes('ადმინი') && html.includes('მომხმარებლის ძებნა'));
  check('chat page is dark themed', html.includes('--bg:#0A0D14'));
  const health = await req('GET', '/api/health');
  const hData = await health.json();
  check('GET /api/health 200', health.status === 200 && hData.service === 'web-chat');
  const nf = await req('GET', '/nope');
  check('unknown route 404', nf.status === 404);
}

// ---------- register: first user is admin, validation, duplicates ----------
let shaoCookie, lukaCookie, gioCookie;
{
  const r1 = await register('shao', 'shao-pass-1', '10.0.1.1');
  check('register first user 200', r1.res.status === 200, 'status=' + r1.res.status + ' ' + JSON.stringify(r1.data));
  check('first registered user is admin', r1.data.is_admin === true && r1.data.username === 'shao');
  check('register sets session cookie', r1.cookie !== null);
  shaoCookie = r1.cookie;

  const r2 = await register('luka', 'luka-pass-2', '10.0.1.2');
  check('register second user 200', r2.res.status === 200);
  check('second registered user is NOT admin', r2.data.is_admin === false);
  lukaCookie = r2.cookie;

  const r3 = await register('gio', 'same-password', '10.0.1.3');
  check('register third user 200', r3.res.status === 200);
  gioCookie = r3.cookie;

  const dup = await register('shao', 'other-pass', '10.0.1.4');
  check('register duplicate username 400', dup.res.status === 400, 'status=' + dup.res.status);
  const dupCase = await register('SHAO', 'other-pass', '10.0.1.4');
  check('username is case-insensitive (SHAO = shao)', dupCase.res.status === 400, 'status=' + dupCase.res.status);
  const short = await register('ab', 'pass1234', '10.0.1.5');
  check('register rejects username < 3 chars', short.res.status === 400);
  const badChars = await register('nika!', 'pass1234', '10.0.1.5');
  check('register rejects username with bad chars', badChars.res.status === 400);
  const georgian = await register('ნიკა', 'pass1234', '10.0.1.5');
  check('register rejects non-latin username', georgian.res.status === 400);
  const shortPass = await register('dato', 'abc', '10.0.1.5');
  check('register rejects password < 4 chars', shortPass.res.status === 400);
  const missing = await register('dato', '', '10.0.1.5');
  check('register rejects empty password', missing.res.status === 400);
}

// ---------- password hash verification (never plain text) ----------
{
  const rows = db.prepare('SELECT username, password_hash FROM users ORDER BY username').all();
  check('3 users stored', rows.length === 3, 'n=' + rows.length);
  check('stored hashes are pbkdf2$100000$ format', rows.every((r) => r.password_hash.startsWith('pbkdf2$100000$')), rows.map((r) => r.password_hash.slice(0, 20)).join(','));
  check('stored hash is not the plain password', rows.every((r) => r.password_hash !== 'shao-pass-1' && r.password_hash !== 'luka-pass-2' && r.password_hash !== 'same-password'));
  // gio used 'same-password'; register another user with the same password —
  // per-user salts must make the hashes differ.
  const r = await register('ana', 'same-password', '10.0.1.6');
  check('fourth user registers 200', r.res.status === 200);
  const hashes = db.prepare("SELECT password_hash FROM users WHERE password_hash LIKE 'pbkdf2$%'").all().map((x) => x.password_hash);
  const gioHash = db.prepare("SELECT password_hash FROM users WHERE username = 'gio'").get().password_hash;
  const anaHash = db.prepare("SELECT password_hash FROM users WHERE username = 'ana'").get().password_hash;
  check('same password, different salts => different hashes', gioHash !== anaHash);
  check('all 4 hashes unique', new Set(hashes).size === 4, 'unique=' + new Set(hashes).size);
}

// ---------- login: wrong password / unknown user / correct ----------
{
  const bad = await login('shao', 'wrong-password', '10.0.2.1');
  check('login rejects wrong password', bad.res.status === 401, 'status=' + bad.res.status);
  const noUser = await login('ghost', 'whatever', '10.0.2.1');
  check('login rejects unknown username', noUser.res.status === 401);
  check('wrong password and unknown user give the SAME generic error', bad.data.error === noUser.data.error && bad.data.error === 'არასწორი username ან პაროლი.', JSON.stringify(bad.data));
  const good = await login('shao', 'shao-pass-1', '10.0.2.2');
  check('login accepts correct password', good.res.status === 200 && good.data.username === 'shao' && good.data.is_admin === true);
  check('login sets HttpOnly + Secure + SameSite=Lax cookie', /HttpOnly/.test(good.res.headers.get('set-cookie') || '') && /Secure/.test(good.res.headers.get('set-cookie') || '') && /SameSite=Lax/.test(good.res.headers.get('set-cookie') || ''));
  const badCookie = await req('GET', '/api/me', { ip: '10.0.2.3', headers: { Cookie: 'chat_session=' + '0'.repeat(64) } });
  check('me rejects forged cookie', badCookie.status === 401);
  const noAuth = await req('GET', '/api/me', { ip: '10.0.2.3' });
  check('me rejects unauthenticated', noAuth.status === 401);
  const me = await req('GET', '/api/me', { ip: '10.0.2.3', headers: { Cookie: shaoCookie } });
  const meData = await me.json();
  check('me returns username + is_admin for valid cookie', me.status === 200 && meData.username === 'shao' && meData.is_admin === true);
}

// ---------- user search ----------
{
  const noAuth = await req('GET', '/api/users/search?q=lu', { ip: '10.0.3.1' });
  check('search rejects unauthenticated', noAuth.status === 401);
  const s1 = await req('GET', '/api/users/search?q=lu', { ip: '10.0.3.2', headers: { Cookie: shaoCookie } });
  const s1Data = await s1.json();
  check('search finds user by prefix', s1.status === 200 && s1Data.users.includes('luka'), JSON.stringify(s1Data));
  check('search does not include self', !s1Data.users.includes('shao'));
  const s2 = await req('GET', '/api/users/search?q=zzznobody', { ip: '10.0.3.2', headers: { Cookie: shaoCookie } });
  const s2Data = await s2.json();
  check('search with no match returns empty list', s2.status === 200 && Array.isArray(s2Data.users) && s2Data.users.length === 0);
  const s3 = await req('GET', '/api/users/search?q=', { ip: '10.0.3.2', headers: { Cookie: shaoCookie } });
  const s3Data = await s3.json();
  check('search with empty q returns empty list', s3.status === 200 && s3Data.users.length === 0);
}

// ---------- chat creation: direct + group ----------
let directId, groupId;
{
  const shao = { Cookie: shaoCookie };
  const luka = { Cookie: lukaCookie };
  const noAuth = await req('POST', '/api/chats', { ip: '10.0.4.1', headers: { 'Content-Type': 'application/json' }, body: { type: 'direct', username: 'luka' } });
  check('create chat rejects unauthenticated', noAuth.status === 401);
  const ghost = await req('POST', '/api/chats', { ip: '10.0.4.2', headers: { 'Content-Type': 'application/json', ...shao }, body: { type: 'direct', username: 'ghost' } });
  check('direct chat with unknown user 404', ghost.status === 404);
  const self = await req('POST', '/api/chats', { ip: '10.0.4.2', headers: { 'Content-Type': 'application/json', ...shao }, body: { type: 'direct', username: 'shao' } });
  check('direct chat with self 400', self.status === 400);
  const badType = await req('POST', '/api/chats', { ip: '10.0.4.2', headers: { 'Content-Type': 'application/json', ...shao }, body: { type: 'weird' } });
  check('create chat rejects unknown type', badType.status === 400);

  const d1 = await req('POST', '/api/chats', { ip: '10.0.4.3', headers: { 'Content-Type': 'application/json', ...shao }, body: { type: 'direct', username: 'luka' } });
  const d1Data = await d1.json();
  check('direct chat create 200, title = peer username', d1.status === 200 && d1Data.title === 'luka' && d1Data.is_group === false, JSON.stringify(d1Data));
  directId = d1Data.chat_id;
  check('direct chat id is numeric', Number.isInteger(directId) && directId > 0, 'id=' + directId);
  const d2 = await req('POST', '/api/chats', { ip: '10.0.4.3', headers: { 'Content-Type': 'application/json', ...luka }, body: { type: 'direct', username: 'shao' } });
  const d2Data = await d2.json();
  check('creating the same 1:1 chat again returns the SAME chat', d2.status === 200 && d2Data.chat_id === directId, JSON.stringify(d2Data));

  const noTitle = await req('POST', '/api/chats', { ip: '10.0.4.4', headers: { 'Content-Type': 'application/json', ...shao }, body: { type: 'group', title: '  ', members: ['luka'] } });
  check('group chat rejects empty title', noTitle.status === 400);
  const noMembers = await req('POST', '/api/chats', { ip: '10.0.4.4', headers: { 'Content-Type': 'application/json', ...shao }, body: { type: 'group', title: 'გუნდი', members: [] } });
  check('group chat rejects empty members', noMembers.status === 400);
  const ghostMember = await req('POST', '/api/chats', { ip: '10.0.4.4', headers: { 'Content-Type': 'application/json', ...shao }, body: { type: 'group', title: 'გუნდი', members: ['luka', 'ghost'] } });
  check('group chat rejects unknown member', ghostMember.status === 404);
  const selfMember = await req('POST', '/api/chats', { ip: '10.0.4.4', headers: { 'Content-Type': 'application/json', ...shao }, body: { type: 'group', title: 'გუნდი', members: ['luka', 'shao'] } });
  check('group chat rejects self in members', selfMember.status === 400);

  const g1 = await req('POST', '/api/chats', { ip: '10.0.4.5', headers: { 'Content-Type': 'application/json', ...shao }, body: { type: 'group', title: 'ჩვენი გუნდი', members: ['luka', 'gio', 'luka'] } });
  const g1Data = await g1.json();
  check('group chat create 200 with title', g1.status === 200 && g1Data.title === 'ჩვენი გუნდი' && g1Data.is_group === true, JSON.stringify(g1Data));
  groupId = g1Data.chat_id;
  const members = db.prepare('SELECT user_id FROM chat_members WHERE chat_id = ?').all(groupId);
  check('group has creator + 2 unique members (dupes ignored)', members.length === 3, 'n=' + members.length);
}

// ---------- list chats: titles per viewer + unread ----------
{
  const shaoList = await req('GET', '/api/chats', { ip: '10.0.5.1', headers: { Cookie: shaoCookie } });
  const shaoData = await shaoList.json();
  check('list chats 200 for shao', shaoList.status === 200 && shaoData.chats.length === 2, 'n=' + (shaoData.chats && shaoData.chats.length));
  const shaoDirect = shaoData.chats.find((c) => c.id === directId);
  const shaoGroup = shaoData.chats.find((c) => c.id === groupId);
  check('direct chat title for shao = luka', shaoDirect && shaoDirect.title === 'luka', JSON.stringify(shaoDirect));
  check('group chat title = stored title', shaoGroup && shaoGroup.title === 'ჩვენი გუნდი');
  check('direct members = shao + luka', shaoDirect && shaoDirect.members.length === 2 && shaoDirect.members.includes('shao') && shaoDirect.members.includes('luka'));
  check('fresh chats have 0 unread', shaoData.chats.every((c) => c.unread === 0));

  const lukaList = await req('GET', '/api/chats', { ip: '10.0.5.2', headers: { Cookie: lukaCookie } });
  const lukaData = await lukaList.json();
  const lukaDirect = lukaData.chats.find((c) => c.id === directId);
  check('direct chat title for luka = shao (other side)', lukaDirect && lukaDirect.title === 'shao', JSON.stringify(lukaDirect));

  const gioList = await req('GET', '/api/chats', { ip: '10.0.5.3', headers: { Cookie: gioCookie } });
  const gioData = await gioList.json();
  check('gio sees only the group chat (not the 1:1)', gioData.chats.length === 1 && gioData.chats[0].id === groupId, 'n=' + gioData.chats.length);
  const noAuth = await req('GET', '/api/chats', { ip: '10.0.5.4' });
  check('list chats rejects unauthenticated', noAuth.status === 401);
}

// ---------- messages: send / read / unread / polling ----------
{
  const shao = { Cookie: shaoCookie };
  const luka = { Cookie: lukaCookie };
  const gio = { Cookie: gioCookie };

  const ghost = await req('POST', '/api/chats/' + directId + '/messages', { ip: '10.0.6.1', headers: { 'Content-Type': 'application/json', ...gio }, body: { body: 'hello?' } });
  check('non-member cannot send to a chat', ghost.status === 403);
  const empty = await req('POST', '/api/chats/' + directId + '/messages', { ip: '10.0.6.1', headers: { 'Content-Type': 'application/json', ...shao }, body: { body: '   ' } });
  check('empty message rejected', empty.status === 400);
  const tooLong = await req('POST', '/api/chats/' + directId + '/messages', { ip: '10.0.6.1', headers: { 'Content-Type': 'application/json', ...shao }, body: { body: 'x'.repeat(2001) } });
  check('message > 2000 chars rejected', tooLong.status === 400);
  const noChat = await req('POST', '/api/chats/99999/messages', { ip: '10.0.6.1', headers: { 'Content-Type': 'application/json', ...shao }, body: { body: 'hi' } });
  check('send to unknown chat 404', noChat.status === 404);

  const m1 = await req('POST', '/api/chats/' + directId + '/messages', { ip: '10.0.6.2', headers: { 'Content-Type': 'application/json', ...shao }, body: { body: 'გამარჯობა ლუკა' } });
  const m1Data = await m1.json();
  check('send message 200', m1.status === 200 && m1Data.ok === true && Number.isInteger(m1Data.id), JSON.stringify(m1Data));

  // Unread: luka has not opened the direct chat since shao's message.
  const lukaListEarly = await req('GET', '/api/chats', { ip: '10.0.6.4', headers: { Cookie: lukaCookie } });
  const lukaDataEarly = await lukaListEarly.json();
  const lukaDirectEarly = lukaDataEarly.chats.find((c) => c.id === directId);
  check('unread = 1 for luka after shao message', lukaDirectEarly && lukaDirectEarly.unread === 1, JSON.stringify(lukaDirectEarly));
  check('last message shown in list', lukaDirectEarly && lukaDirectEarly.last_message === 'გამარჯობა ლუკა' && lukaDirectEarly.last_username === 'shao');

  const m2 = await req('POST', '/api/chats/' + directId + '/messages', { ip: '10.0.6.2', headers: { 'Content-Type': 'application/json', ...luka }, body: { body: 'გამარჯობა შაო' } });
  check('peer can reply 200', m2.status === 200);
  const m3 = await req('POST', '/api/chats/' + groupId + '/messages', { ip: '10.0.6.3', headers: { 'Content-Type': 'application/json', ...gio }, body: { body: 'გუნდში ყველას გამარჯობა' } });
  check('group member can send 200', m3.status === 200);

  // Luka replied, so his own send marked the chat read for him.
  const lukaList = await req('GET', '/api/chats', { ip: '10.0.6.4', headers: { Cookie: lukaCookie } });
  const lukaData = await lukaList.json();
  const lukaDirect = lukaData.chats.find((c) => c.id === directId);
  check('unread = 0 for luka after his own reply (send marks read)', lukaDirect && lukaDirect.unread === 0, JSON.stringify(lukaDirect));

  const read = await req('GET', '/api/chats/' + directId + '/messages', { ip: '10.0.6.5', headers: { Cookie: lukaCookie } });
  const readData = await read.json();
  check('read messages 200 with chat + 2 messages', read.status === 200 && readData.messages.length === 2, 'n=' + (readData.messages && readData.messages.length));
  check('messages in chronological order', readData.messages[0].body === 'გამარჯობა ლუკა' && readData.messages[1].body === 'გამარჯობა შაო');
  check('mine flag correct per viewer', readData.messages[0].mine === false && readData.messages[1].mine === true);
  check('chat title in read response = shao for luka', readData.chat.title === 'shao');

  const lukaList2 = await req('GET', '/api/chats', { ip: '10.0.6.4', headers: { Cookie: lukaCookie } });
  const lukaData2 = await lukaList2.json();
  const lukaDirect2 = lukaData2.chats.find((c) => c.id === directId);
  check('unread = 0 after reading', lukaDirect2 && lukaDirect2.unread === 0, JSON.stringify(lukaDirect2));

  // Polling with after=: only newer messages.
  const m4 = await req('POST', '/api/chats/' + directId + '/messages', { ip: '10.0.6.6', headers: { 'Content-Type': 'application/json', ...shao }, body: { body: 'კიდევ ერთი' } });
  const m4Data = await m4.json();
  const poll = await req('GET', '/api/chats/' + directId + '/messages?after=' + m1Data.id, { ip: '10.0.6.7', headers: { Cookie: lukaCookie } });
  const pollData = await poll.json();
  check('polling after= returns only newer messages', poll.status === 200 && pollData.messages.length === 2 && pollData.messages[1].id === m4Data.id, JSON.stringify(pollData.messages.map((m) => m.id)));
  const pollNone = await req('GET', '/api/chats/' + directId + '/messages?after=' + m4Data.id, { ip: '10.0.6.7', headers: { Cookie: lukaCookie } });
  const pollNoneData = await pollNone.json();
  check('polling after=latest returns empty', pollNone.status === 200 && pollNoneData.messages.length === 0);

  const nonMemberRead = await req('GET', '/api/chats/' + directId + '/messages', { ip: '10.0.6.8', headers: { Cookie: gioCookie } });
  check('non-member cannot read a chat', nonMemberRead.status === 403);
  const noChatRead = await req('GET', '/api/chats/99999/messages', { ip: '10.0.6.8', headers: { Cookie: shaoCookie } });
  check('read unknown chat 404', noChatRead.status === 404);
}

// ---------- admin overview + admin chat view ----------
{
  const shao = { Cookie: shaoCookie };
  const luka = { Cookie: lukaCookie };

  const noAuth = await req('GET', '/api/admin/overview', { ip: '10.0.7.1' });
  check('admin overview rejects unauthenticated', noAuth.status === 401);
  const notAdmin = await req('GET', '/api/admin/overview', { ip: '10.0.7.2', headers: { Cookie: lukaCookie } });
  check('admin overview rejects non-admin', notAdmin.status === 403, 'status=' + notAdmin.status);

  const ov = await req('GET', '/api/admin/overview', { ip: '10.0.7.3', headers: { Cookie: shaoCookie } });
  const ovData = await ov.json();
  check('admin overview 200 for admin', ov.status === 200, 'status=' + ov.status);
  check('admin sees ALL chats (2)', ovData.chats.length === 2, 'n=' + (ovData.chats && ovData.chats.length));
  const ovDirect = ovData.chats.find((c) => c.id === directId);
  const ovGroup = ovData.chats.find((c) => c.id === groupId);
  check('admin direct chat title = both members', ovDirect && ovDirect.title === 'luka ↔ shao', JSON.stringify(ovDirect));
  check('admin group chat title = stored title', ovGroup && ovGroup.title === 'ჩვენი გუნდი');
  check('admin sees message counts', ovDirect && ovDirect.message_count === 3 && ovGroup && ovGroup.message_count === 1, JSON.stringify(ovData.chats.map((c) => c.message_count)));
  check('admin sees members per chat', ovDirect && ovDirect.members.length === 2 && ovGroup && ovGroup.members.length === 3);
  check('admin sees ALL users (4)', ovData.users.length === 4, 'n=' + (ovData.users && ovData.users.length));
  check('admin users list marks admin', ovData.users.find((u) => u.username === 'shao').is_admin === true && ovData.users.find((u) => u.username === 'luka').is_admin === false);

  const adminRead = await req('GET', '/api/admin/chats/' + directId + '/messages', { ip: '10.0.7.4', headers: { Cookie: shaoCookie } });
  const adminReadData = await adminRead.json();
  check('admin can enter any chat and read messages', adminRead.status === 200 && adminReadData.messages.length === 3, 'n=' + (adminReadData.messages && adminReadData.messages.length));
  const adminReadNo = await req('GET', '/api/admin/chats/' + directId + '/messages', { ip: '10.0.7.5', headers: { Cookie: lukaCookie } });
  check('non-admin cannot use admin chat view', adminReadNo.status === 403);
  const adminReadGhost = await req('GET', '/api/admin/chats/99999/messages', { ip: '10.0.7.4', headers: { Cookie: shaoCookie } });
  check('admin chat view unknown chat 404', adminReadGhost.status === 404);
}

// ---------- logout ----------
{
  const out = await req('POST', '/api/logout', { ip: '10.0.8.1', headers: { Cookie: gioCookie } });
  check('logout 200', out.status === 200);
  check('logout clears cookie', (out.headers.get('set-cookie') || '').includes('Max-Age=0'));
  const me = await req('GET', '/api/me', { ip: '10.0.8.2', headers: { Cookie: gioCookie } });
  check('session dead after logout', me.status === 401);
}

// ---------- origin check + rate limits ----------
{
  const cross = await req('POST', '/api/login', { ip: '10.0.9.1', headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' }, body: { username: 'shao', password: 'shao-pass-1' } });
  check('login rejects cross-site Origin', cross.status === 403);
  const crossReg = await req('POST', '/api/register', { ip: '10.0.9.1', headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' }, body: { username: 'evil1', password: 'pass1234' } });
  check('register rejects cross-site Origin', crossReg.status === 403);

  let statuses = [];
  for (let i = 0; i < 6; i++) {
    const r = await req('POST', '/api/login', { ip: '10.0.9.2', headers: { 'Content-Type': 'application/json' }, body: { username: 'shao', password: 'wrong' } });
    statuses.push(r.status);
  }
  check('login rate limit: 5 attempts then 429', statuses.slice(0, 5).every((s) => s === 401) && statuses[5] === 429, statuses.join(','));

  let regStatuses = [];
  for (let i = 0; i < 6; i++) {
    const r = await req('POST', '/api/register', { ip: '10.0.9.3', headers: { 'Content-Type': 'application/json' }, body: { username: 'u' + i, password: 'pass1234' } });
    regStatuses.push(r.status);
  }
  check('register rate limit: 5 attempts then 429', regStatuses.slice(0, 5).every((s) => s === 400 || s === 200) && regStatuses[5] === 429, regStatuses.join(','));
  // NOTE: 'u0'..'u4' usernames are 2 chars -> 400 validation; the 6th is
  // still counted by the limiter, which is what this check proves.
}

// ---------- inline script hygiene (lives inside a JS template literal) ----------
{
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8');
  const scriptStart = src.indexOf('\n<script>\n');
  const scriptEnd = src.indexOf('</script>', scriptStart);
  const inline = src.slice(scriptStart, scriptEnd);
  check('inline script found in source', scriptStart > 0 && scriptEnd > scriptStart);
  check('inline script has no backticks', !inline.includes('`'));
  check('inline script has no ${} interpolations', !inline.includes('${'));
}

// ---------- summary ----------
console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) {
  console.log('Failures: ' + failures.join(', '));
  process.exit(1);
}

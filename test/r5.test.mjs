import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// ---- 2단계: 자료를 코드 밖으로 ----
import { readFileSync } from 'node:fs';
import { createNotesApi } from '../src/notes-handler.mjs';
import { createNotesStore, NotesStoreError } from '../src/notes-store.mjs';

const step2 = { ...config, step: 2 };
// 비밀값 검사에 걸리지 않도록 가짜 키는 실행 중에 조립한다.
const FAKE_KEY = ['sb', 'secret', 'testonlyvalue123456'].join('_');
const goodEnv = { SUPABASE_URL: 'https://example-project.supabase.co', SUPABASE_SECRET_KEY: FAKE_KEY };

function fakeRes() {
  return {
    statusCode: 0, headers: {}, body: undefined,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

test('step 2 build identity records the step and still rejects bad input', () => {
  assert.equal(deploymentIdentity(env, step2).step, 2);
  assert.equal(deploymentIdentity(env, { ...config, step: 3 }).step, 3);
  assert.equal(deploymentIdentity(env, { ...config, step: 4 }).step, 4);
  assert.throws(() => deploymentIdentity(env, { ...config, step: 5 }));
});

test('screen reads the server function and the public files hold no notes', () => {
  const page = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.ok(page.includes("api('/api/notes'") && page.includes('`/api/notes/${note.id}`'));
  assert.ok(!page.includes('/data.json'));
  assert.ok(!/SUPABASE|sb_secret_/u.test(page));
  for (const file of ['../data.json', '../public/data.json']) {
    const data = JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
    assert.deepEqual(data.notes, []);
  }
});

test('step 2 attack check records what was observed without note bodies', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => {
      const path = new URL(String(url)).pathname;
      const body = path === '/api/notes'
        ? { notes: [{ title: 'T', content: 'BODY_SHOULD_NOT_APPEAR' }] } : { notes: [] };
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const results = await runAttackChecks(step2);
    assert.deepEqual(results.map((item) => item.attackId),
      ['static_data_json_read', 'anonymous_api_read', 'api_key_not_exposed']);
    assert.match(results[0].observed, /보이지 않음/u);
    assert.match(results[1].observed, /메모 1건이 응답됨/u);
    assert.match(results[2].observed, /값이 없음/u);
    assert.ok(!JSON.stringify(results).includes('BODY_SHOULD_NOT_APPEAR'));
    globalThis.fetch = async (url) => new Response(
      JSON.stringify(new URL(String(url)).pathname === '/api/notes' ? { notes: [], leak: FAKE_KEY } : { notes: [] }),
      { status: 200 });
    const [, , leaked] = await runAttackChecks(step2);
    assert.match(leaked.observed, /키로 보이는 값이 있음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// ---- 3단계: 이메일·비밀번호 로그인·로그아웃 화면 ----
import { checkAuthConfig, describeAuthError, mountAuthPanel } from '../public/auth.js';
import { AUTH_CONFIG } from '../public/auth-config.js';

const goodAuth = { url: 'https://abcdefghij.supabase.co', publishableKey: ['sb', 'publishable', 'testonly'].join('_') };
const b64url = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

test('auth config accepts only public values and refuses server-only keys', () => {
  assert.equal(checkAuthConfig({ url: '', publishableKey: '' }).ok, false);
  assert.equal(checkAuthConfig({ ...goodAuth, url: 'http://abcdefghij.supabase.co' }).ok, false);
  assert.equal(checkAuthConfig({ ...goodAuth, url: 'https://abcdefghij.supabase.co/rest/v1' }).ok, false);
  const secret = checkAuthConfig({ ...goodAuth, publishableKey: ['sb', 'secret', 'testonly'].join('_') });
  assert.equal(secret.ok, false);
  assert.match(secret.reason, /서버 전용 키/u);
  const serviceJwt = `${b64url({ alg: 'HS256' })}.${b64url({ role: 'service_role' })}.sig`;
  assert.equal(checkAuthConfig({ ...goodAuth, publishableKey: serviceJwt }).ok, false);
  const anonJwt = `${b64url({ alg: 'HS256' })}.${b64url({ role: 'anon' })}.sig`;
  assert.equal(checkAuthConfig({ ...goodAuth, publishableKey: anonJwt }).ok, true);
  assert.equal(checkAuthConfig(goodAuth).ok, true);
  assert.ok(!/서버 전용 키/u.test(checkAuthConfig(AUTH_CONFIG).reason ?? ''), '저장소의 설정 파일에 서버 전용 키가 있으면 안 됩니다');
});

test('login failures are explained on screen without leaking input', () => {
  assert.match(describeAuthError({ code: 'invalid_credentials', status: 400 }), /이메일 또는 비밀번호가 맞지 않습니다/u);
  assert.match(describeAuthError({ code: 'email_not_confirmed', status: 400 }), /이메일 인증/u);
  assert.match(describeAuthError({ code: 'over_request_rate_limit', status: 429 }), /너무 많습니다/u);
  assert.match(describeAuthError({ name: 'AuthRetryableFetchError', status: 0 }), /연결하지 못했습니다/u);
  assert.match(describeAuthError({ status: 401, code: 'bad_api_key' }), /공개용 키/u);
  assert.match(describeAuthError(new Error('boom password=hunter2')), /로그인하지 못했습니다/u);
  assert.ok(!describeAuthError(new Error('boom password=hunter2')).includes('hunter2'));
});

function fakeEl() {
  const handlers = {};
  return { textContent: '', dataset: {}, hidden: false, disabled: false, value: '',
    addEventListener(type, handler) { handlers[type] = handler; },
    fire(type, event = { preventDefault() {} }) { return handlers[type](event); } };
}
function fakePanel() {
  const names = ['badge', 'message', 'form', 'email', 'password', 'submit', 'signedIn', 'who', 'logout'];
  const els = Object.fromEntries(names.map((name) => [name, fakeEl()]));
  const attr = { badge: 'auth-badge', message: 'auth-message', form: 'auth-form', email: 'auth-email',
    password: 'auth-password', submit: 'auth-submit', signedIn: 'auth-signed-in', who: 'auth-who', logout: 'auth-logout' };
  const bySelector = Object.fromEntries(names.map((name) => [`[data-${attr[name]}]`, els[name]]));
  const body = { dataset: {} };
  return { els, body, root: { querySelector: (selector) => bySelector[selector], ownerDocument: { body } } };
}
function fakeSdk(signIn) {
  const listeners = [];
  const calls = { signIn: [], clientArgs: null };
  return { calls, sdk: { createClient(...args) {
    calls.clientArgs = args;
    return { auth: {
      onAuthStateChange(callback) { listeners.push(callback); return { data: { subscription: {} } }; },
      getSession: async () => ({ data: { session: null } }),
      signInWithPassword: async (credentials) => {
        calls.signIn.push(credentials);
        const result = signIn(credentials);
        if (!result.error) listeners.forEach((callback) => callback('SIGNED_IN', result.session));
        return { error: result.error ?? null };
      },
      signOut: async () => { listeners.forEach((callback) => callback('SIGNED_OUT', null)); return { error: null }; },
    } };
  } } };
}

test('screen state differs between logged in and logged out', async () => {
  const panel = fakePanel();
  const { sdk, calls } = fakeSdk(() => ({ session: { user: { email: 'tester@example.test' } } }));
  assert.equal(mountAuthPanel({ root: panel.root, config: goodAuth, sdk }).ok, true);
  assert.deepEqual(calls.clientArgs[2].auth, { persistSession: true, autoRefreshToken: true, detectSessionInUrl: false });
  assert.equal(panel.body.dataset.auth, 'out');
  assert.equal(panel.els.badge.textContent, '로그아웃 상태');
  assert.equal(panel.els.form.hidden, false);
  assert.equal(panel.els.signedIn.hidden, true);

  panel.els.email.value = 'tester@example.test';
  panel.els.password.value = 'correct horse';
  await panel.els.form.fire('submit');
  assert.deepEqual(calls.signIn, [{ email: 'tester@example.test', password: 'correct horse' }]);
  assert.equal(panel.body.dataset.auth, 'in');
  assert.equal(panel.els.badge.textContent, '로그인 상태');
  assert.equal(panel.els.who.textContent, 'tester@example.test');
  assert.equal(panel.els.form.hidden, true);
  assert.equal(panel.els.signedIn.hidden, false);
  assert.equal(panel.els.password.value, '');

  await panel.els.logout.fire('click');
  assert.equal(panel.body.dataset.auth, 'out');
  assert.equal(panel.els.badge.textContent, '로그아웃 상태');
  assert.equal(panel.els.who.textContent, '');
  assert.equal(panel.els.form.hidden, false);
  assert.equal(panel.els.signedIn.hidden, true);
});

test('failed login shows the reason, stays logged out and never prints the password', async () => {
  const panel = fakePanel();
  const { sdk } = fakeSdk(() => ({ error: { code: 'invalid_credentials', status: 400 } }));
  mountAuthPanel({ root: panel.root, config: goodAuth, sdk });
  panel.els.email.value = 'tester@example.test';
  panel.els.password.value = 'wrong password value';
  await panel.els.form.fire('submit');
  assert.equal(panel.body.dataset.auth, 'out');
  assert.match(panel.els.message.textContent, /이메일 또는 비밀번호가 맞지 않습니다/u);
  assert.equal(panel.els.message.dataset.kind, 'error');
  assert.ok(!panel.els.message.textContent.includes('wrong password value'));
  assert.equal(panel.els.password.value, '');
  assert.equal(panel.els.submit.disabled, false);
  panel.els.email.value = '';
  await panel.els.form.fire('submit');
  assert.match(panel.els.message.textContent, /모두 입력/u);
});

test('missing or secret config never creates a client', () => {
  for (const config of [{ url: '', publishableKey: '' }, { ...goodAuth, publishableKey: ['sb', 'secret', 'x'].join('_') }]) {
    const panel = fakePanel();
    const { sdk, calls } = fakeSdk(() => ({}));
    assert.equal(mountAuthPanel({ root: panel.root, config, sdk }).ok, false);
    assert.equal(calls.clientArgs, null);
    assert.equal(panel.els.form.hidden, true);
    assert.equal(panel.els.message.dataset.kind, 'error');
  }
});

test('login page loads the same-origin SDK and keeps secrets out of browser files', () => {
  const page = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.ok(page.includes('/vendor/supabase.js') && page.includes('/auth.js') && page.includes('data-auth-logout'));
  assert.ok(!/https?:\/\/(?!www\.w3\.org)[^"' ]*(cdn|unpkg|esm\.sh)/iu.test(page));
  for (const file of ['../public/auth.js', '../public/auth-config.js']) {
    const source = readFileSync(new URL(file, import.meta.url), 'utf8');
    assert.ok(!/localStorage|sessionStorage|document\.cookie/u.test(source), `${file}가 토큰을 직접 저장하면 안 됩니다`);
    assert.ok(!/sb_secret_[A-Za-z0-9_-]{8,}/u.test(source));
  }
});

test('hidden panels really disappear even when a rule sets display on them', () => {
  const page = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(page, /\[hidden\]\s*\{\s*display:\s*none\s*!important/u);
});


// ---- 3단계: 로그인 검사 + 가상 메모 추가·조회·수정·삭제 API ----
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SignJWT, generateKeyPair } from 'jose';
import { createLoginVerifier } from '../src/verify-login.mjs';

const realConfig = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const studentIssuer = realConfig.identityProvider.issuer;
const unsignedToken = (payload) => `${b64url({ alg: 'ES256', typ: 'JWT' })}.${b64url(payload)}.c2ln`;
const nowSec = () => Math.floor(Date.now() / 1000);
const studentClaims = (sub, extra = {}) => ({ iss: studentIssuer, aud: 'authenticated', role: 'authenticated',
  sub, exp: nowSec() + 600, ...extra });
const noJudgeKeys = async () => { throw new Error('no_judge_key'); };
const IDS = { missing: randomUUID(), other: randomUUID() };

// 로그인한 사용자 두 명(A, B)과 메모리 안의 가짜 자료 저장소. 실제 DB처럼 쓰기·삭제에 소유자 조건을 건다.
// filterOwner=false이면 저장소가 소유자 조건을 빼먹은 것처럼 동작해서, 처리기 쪽 검사만으로도 막히는지 시험한다.
function memoryStore({ filterOwner = true } = {}) {
  const rows = new Map();
  const calls = [];
  const view = ({ id, title, body }) => ({ id, title, body });
  const sameOwner = (row, ownerId) => !filterOwner || row.owner_id === ownerId;
  return { rows, calls, store: {
    async list(ownerId) { calls.push('list'); return [...rows.values()].filter((row) => row.owner_id === ownerId).map(view); },
    async get(id) { calls.push('get'); return rows.has(id) ? { ...view(rows.get(id)), ownerId: rows.get(id).owner_id } : null; },
    async create({ id, ownerId, title, body }) {
      calls.push('create');
      if (rows.has(id)) throw new NotesStoreError({ code: '23505' });
      rows.set(id, { id, owner_id: ownerId, title, body });
      return id;
    },
    async update(id, ownerId, { title, body }) {
      calls.push('update');
      if (!rows.has(id) || !sameOwner(rows.get(id), ownerId)) return false;
      Object.assign(rows.get(id), { title, body });
      return true;
    },
    async remove(id, ownerId) {
      calls.push('remove');
      if (!rows.has(id) || !sameOwner(rows.get(id), ownerId)) return false;
      return rows.delete(id);
    },
  } };
}

function apiHarness({ judgeKeySet = noJudgeKeys, createStore, extra = {}, filterOwner = true } = {}) {
  const users = {
    A: { sub: randomUUID(), token: null },
    B: { sub: randomUUID(), token: null },
  };
  for (const user of Object.values(users)) user.token = unsignedToken({ iss: studentIssuer, sub: user.sub, n: randomUUID() });
  const claimsByToken = new Map(Object.values(users).map((user) => [user.token, studentClaims(user.sub)]));
  const memory = memoryStore({ filterOwner });
  const seen = { logs: [], clientCalls: 0, getClaims: [] };
  const supabaseClient = { auth: { getClaims: async (token) => {
    seen.getClaims.push(token);
    return claimsByToken.has(token) ? { data: { claims: claimsByToken.get(token) }, error: null }
      : { data: null, error: { message: 'invalid jwt' } };
  } } };
  const api = createNotesApi({
    env: goodEnv, log: (message) => seen.logs.push(message), loadConfig: () => realConfig,
    createVerifier: (options) => createLoginVerifier({ ...options, supabaseClient, judgeKeySet }),
    createClient: () => { seen.clientCalls += 1; return {}; },
    createStore: createStore ?? (() => memory.store),
    ...extra,
  });
  return { api, users, memory, seen };
}
const bearer = (user) => ({ authorization: `Bearer ${user.token}` });
async function send(handler, { method = 'GET', headers = {}, query, body } = {}) {
  const res = fakeRes();
  await handler({ method, headers, query, body }, res);
  return res;
}
const add = async (h, user, note) => (await send(h.api.collection, { method: 'POST', headers: bearer(user), body: note })).body.id;

test('allowedRoutes lists the real GET POST PUT DELETE paths and each one exists', async () => {
  const expected = ['GET /api/notes', 'POST /api/notes', 'GET /api/notes/:id', 'PUT /api/notes/:id', 'DELETE /api/notes/:id'];
  assert.deepEqual([...realConfig.allowedRoutes].sort(), [...expected].sort());
  const h = apiHarness();
  for (const route of realConfig.allowedRoutes) {
    const [method, path] = route.split(' ');
    const handler = path === '/api/notes' ? h.api.collection : h.api.item;
    const res = await send(handler, { method });
    assert.notEqual(res.statusCode, 405, `${route}는 구현돼 있어야 합니다`);
  }
  assert.equal((await send(h.api.collection, { method: 'PUT' })).headers.Allow, 'GET, POST');
  assert.equal((await send(h.api.item, { method: 'POST' })).headers.Allow, 'GET, PUT, DELETE');
  const vercel = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url), 'utf8'));
  for (const file of ['api/notes.js', 'api/notes/[id].js']) {
    assert.equal(vercel.functions[file].includeFiles, 'aleph.config.json');
    assert.ok(readFileSync(new URL(`../${file}`, import.meta.url), 'utf8').includes('loadConfig'));
  }
});

test('identityProvider records the public issuer data the check uses, without any key', () => {
  const idp = realConfig.identityProvider;
  assert.deepEqual(Object.keys(idp).sort(), ['audience', 'issuer', 'jwksUrl']);
  assert.equal(idp.issuer, `${AUTH_CONFIG.url}/auth/v1`);
  assert.equal(idp.jwksUrl, `${idp.issuer}/.well-known/jwks.json`);
  assert.equal(idp.audience, 'authenticated');
  assert.ok(!/sb_secret_|service_role|SECRET/iu.test(JSON.stringify(idp)));
});

test('every route refuses requests without a valid login and never touches the data', async () => {
  const bad = [
    {},
    { authorization: 'Basic abc' },
    { authorization: 'Bearer not-a-jwt' },
    { authorization: `Bearer ${unsignedToken({ iss: 'https://evil.example/auth/v1', sub: randomUUID() })}` },
    { authorization: `Bearer ${unsignedToken({ iss: studentIssuer, sub: randomUUID() })}` }, // 발급자가 모르는 토큰
    { 'x-user-id': randomUUID(), 'x-role': 'admin' },
  ];
  const routes = [
    ['collection', 'GET', undefined, undefined], ['collection', 'POST', undefined, { title: 't', body: 'b', owner_id: randomUUID(), role: 'admin' }],
    ['item', 'GET', { id: IDS.other }], ['item', 'PUT', { id: IDS.other }, { title: 't', body: 'b' }], ['item', 'DELETE', { id: IDS.other }],
  ];
  for (const headers of bad) {
    const h = apiHarness();
    for (const [which, method, query, body] of routes) {
      const res = await send(h.api[which], { method, headers, query: { ...query, role: 'admin', userId: randomUUID() }, body });
      assert.equal(res.statusCode, 401, `${which} ${method}`);
      assert.deepEqual(res.body, { error: 'unauthorized' });
      assert.equal(res.headers['WWW-Authenticate'], 'Bearer');
    }
    assert.deepEqual(h.memory.calls, [], '검사 전에 자료 저장소를 쓰면 안 됩니다');
    assert.equal(h.seen.clientCalls, 0);
  }
});

test('A adds a note: the server stores the verified user id as owner_id and returns {id}', async () => {
  const h = apiHarness();
  const res = await send(h.api.collection, { method: 'POST', headers: bearer(h.users.A), body: { title: ' 첫 메모 ', body: '가상 내용' } });
  assert.equal(res.statusCode, 201);
  assert.deepEqual(Object.keys(res.body), ['id']);
  assert.match(res.body.id, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u);
  assert.deepEqual(h.memory.rows.get(res.body.id), { id: res.body.id, owner_id: h.users.A.sub, title: '첫 메모', body: '가상 내용' });
  assert.deepEqual(h.seen.getClaims, [h.users.A.token]);
});

test('owner_id, userId and role sent by the browser are ignored', async () => {
  const h = apiHarness();
  const forged = { title: 't', body: 'b', owner_id: h.users.B.sub, userId: h.users.B.sub, role: 'admin', ownerId: h.users.B.sub };
  const res = await send(h.api.collection, { method: 'POST', headers: { ...bearer(h.users.A), 'x-user-id': h.users.B.sub, 'x-role': 'admin' },
    query: { userId: h.users.B.sub, role: 'admin' }, body: forged });
  assert.equal(res.statusCode, 201);
  assert.equal(h.memory.rows.get(res.body.id).owner_id, h.users.A.sub);
  assert.deepEqual(Object.keys(h.memory.rows.get(res.body.id)).sort(), ['body', 'id', 'owner_id', 'title']);
  const list = await send(h.api.collection, { headers: bearer(h.users.B), query: { userId: h.users.A.sub } });
  assert.deepEqual(list.body, []);
});

test('POST accepts a client UUID, rejects duplicates and bad input without storing anything', async () => {
  const h = apiHarness();
  const mine = randomUUID();
  const created = await send(h.api.collection, { method: 'POST', headers: bearer(h.users.A), body: { id: mine.toUpperCase(), title: 't', body: 'b' } });
  assert.equal(created.statusCode, 201);
  assert.deepEqual(created.body, { id: mine });
  const dup = await send(h.api.collection, { method: 'POST', headers: bearer(h.users.B), body: { id: mine, title: 'x', body: 'y' } });
  assert.equal(dup.statusCode, 409);
  assert.deepEqual(h.memory.rows.get(mine), { id: mine, owner_id: h.users.A.sub, title: 't', body: 'b' });
  const before = h.memory.rows.size;
  const invalid = [
    { title: 't', body: 'b', id: 'not-a-uuid' }, { title: 't', body: 'b', id: 7 },
    { body: 'b' }, { title: '   ', body: 'b' }, { title: 'x'.repeat(121), body: 'b' }, { title: 5, body: 'b' },
    { title: 't' }, { title: 't', body: 9 }, { title: 't', body: 'x'.repeat(2001) }, null, [],
  ];
  for (const body of invalid) {
    const res = await send(h.api.collection, { method: 'POST', headers: bearer(h.users.A), body });
    assert.equal(res.statusCode, 400, JSON.stringify(body)?.slice(0, 40));
  }
  assert.equal((await send(h.api.collection, { method: 'POST', headers: bearer(h.users.A), body: '{"title":"문자열 JSON","body":""}' })).statusCode, 201);
  assert.equal(h.memory.rows.size, before + 1);
});

test('list returns only the logged-in user\'s notes as an array of {id,title,body}', async () => {
  const h = apiHarness();
  const first = await add(h, h.users.A, { title: '하나', body: '1' });
  await add(h, h.users.B, { title: 'B의 메모', body: 'b' });
  const second = await add(h, h.users.A, { title: '둘', body: '2' });
  const res = await send(h.api.collection, { headers: bearer(h.users.A) });
  assert.equal(res.statusCode, 200);
  assert.ok(Array.isArray(res.body));
  assert.deepEqual(res.body.map((note) => note.id).sort(), [first, second].sort());
  for (const note of res.body) assert.deepEqual(Object.keys(note).sort(), ['body', 'id', 'title']);
  assert.deepEqual((await send(h.api.collection, { headers: bearer(h.users.B) })).body.map((note) => note.title), ['B의 메모']);
});

test('A reads, edits and deletes a note; after deleting, GET returns 404', async () => {
  const h = apiHarness();
  const id = await add(h, h.users.A, { title: '원래 제목', body: '원래 내용' });
  const one = await send(h.api.item, { headers: bearer(h.users.A), query: { id } });
  assert.equal(one.statusCode, 200);
  assert.deepEqual(one.body, { id, title: '원래 제목', body: '원래 내용' });

  const put = await send(h.api.item, { method: 'PUT', headers: bearer(h.users.A), query: { id }, body: { title: '바뀐 제목', body: '바뀐 내용', owner_id: h.users.A.sub } });
  assert.equal(put.statusCode, 200);
  assert.deepEqual(put.body, { id });
  assert.deepEqual((await send(h.api.item, { headers: bearer(h.users.A), query: { id } })).body, { id, title: '바뀐 제목', body: '바뀐 내용' });
  assert.equal(h.memory.rows.get(id).owner_id, h.users.A.sub, '수정으로 owner_id가 바뀌면 안 됩니다');
  assert.equal((await send(h.api.item, { method: 'PUT', headers: bearer(h.users.A), query: { id }, body: { title: '', body: 'x' } })).statusCode, 400);
  assert.equal((await send(h.api.item, { method: 'PUT', headers: bearer(h.users.A), query: { id }, body: { id: randomUUID(), title: 'x', body: 'y' } })).statusCode, 400);
  assert.equal(h.memory.rows.get(id).title, '바뀐 제목');

  const del = await send(h.api.item, { method: 'DELETE', headers: bearer(h.users.A), query: { id } });
  assert.equal(del.statusCode, 200);
  assert.deepEqual(del.body, { id });
  const gone = await send(h.api.item, { headers: bearer(h.users.A), query: { id } });
  assert.equal(gone.statusCode, 404);
  assert.deepEqual(gone.body, { error: 'not_found' });
  assert.equal((await send(h.api.item, { method: 'DELETE', headers: bearer(h.users.A), query: { id } })).statusCode, 404);
  assert.equal((await send(h.api.item, { method: 'PUT', headers: bearer(h.users.A), query: { id }, body: { title: 't', body: 'b' } })).statusCode, 404);
  assert.deepEqual((await send(h.api.collection, { headers: bearer(h.users.A) })).body, []);
  for (const query of [{}, { id: 'abc' }, { id: [id, id] }]) {
    assert.equal((await send(h.api.item, { headers: bearer(h.users.A), query })).statusCode, 400);
  }
});

const B_NOTE_ID = 'b0b0b0b0-0000-4000-8000-000000000001';
// A와 B가 각자 메모를 가진 상태. B의 메모 id는 SQL로 만든 시험 메모와 같은 고정값이다.
async function twoUsers(options) {
  const h = apiHarness(options);
  const aId = await add(h, h.users.A, { title: 'A의 메모', body: 'A만 봐야 하는 내용' });
  h.memory.rows.set(B_NOTE_ID, { id: B_NOTE_ID, owner_id: h.users.B.sub, title: 'B의 시험 메모', body: 'B만 봐야 하는 내용' });
  return { h, aId, bId: B_NOTE_ID };
}
const snapshot = (h) => JSON.stringify([...h.memory.rows.entries()].sort());

test('A and B keep full access to their own notes', async () => {
  const { h, aId, bId } = await twoUsers();
  for (const [user, id, label] of [[h.users.A, aId, 'A'], [h.users.B, bId, 'B']]) {
    const read = await send(h.api.item, { headers: bearer(user), query: { id } });
    assert.equal(read.statusCode, 200, label);
    assert.deepEqual(Object.keys(read.body).sort(), ['body', 'id', 'title']);
    const edit = await send(h.api.item, { method: 'PUT', headers: bearer(user), query: { id }, body: { title: `${label} 수정`, body: '수정 내용' } });
    assert.deepEqual([edit.statusCode, edit.body], [200, { id }], label);
    assert.equal(h.memory.rows.get(id).owner_id, user.sub, '수정해도 소유자는 그대로여야 합니다');
    assert.equal((await send(h.api.item, { headers: bearer(user), query: { id } })).body.title, `${label} 수정`);
    const created = await send(h.api.collection, { method: 'POST', headers: bearer(user), body: { title: `${label}의 새 메모`, body: 'x' } });
    assert.equal(created.statusCode, 201);
    assert.equal(h.memory.rows.get(created.body.id).owner_id, user.sub);
    assert.equal((await send(h.api.item, { method: 'DELETE', headers: bearer(user), query: { id } })).statusCode, 200);
    assert.equal((await send(h.api.item, { headers: bearer(user), query: { id } })).statusCode, 404);
  }
});

test('the other user cannot read, edit or delete a note, and the refusal looks like a missing note', async () => {
  const { h, aId, bId } = await twoUsers();
  const missing = await send(h.api.item, { headers: bearer(h.users.B), query: { id: IDS.missing } });
  assert.equal(missing.statusCode, 404);
  const before = snapshot(h);
  const attempts = [
    ['B reads A', h.users.B, aId, 'GET'], ['A reads B', h.users.A, bId, 'GET'],
    ['B edits A', h.users.B, aId, 'PUT'], ['A edits B', h.users.A, bId, 'PUT'],
    ['B deletes A', h.users.B, aId, 'DELETE'], ['A deletes B', h.users.A, bId, 'DELETE'],
  ];
  for (const [label, user, id, method] of attempts) {
    const res = await send(h.api.item, { method, headers: bearer(user), query: { id },
      body: method === 'PUT' ? { title: '탈취', body: '탈취' } : undefined });
    assert.equal(res.statusCode, 404, label);
    assert.deepEqual(res.body, missing.body, `${label}: 남의 메모와 없는 메모의 응답이 같아야 합니다`);
    assert.ok(!JSON.stringify(res).includes('만 봐야 하는 내용'), `${label}: 내용이 새면 안 됩니다`);
  }
  assert.equal(snapshot(h), before, '거부된 요청이 자료를 바꾸면 안 됩니다');
  const lists = [await send(h.api.collection, { headers: bearer(h.users.A) }), await send(h.api.collection, { headers: bearer(h.users.B) })];
  assert.deepEqual(lists.map((res) => res.body.map((note) => note.id)), [[aId], [bId]]);
});

test('changing the owner is refused, whether it points at the other user or at no one', async () => {
  const { h, aId } = await twoUsers();
  const before = snapshot(h);
  for (const claim of [{ owner_id: h.users.B.sub }, { ownerId: h.users.B.sub }, { owner_id: '' }, { owner_id: 'someone-else' }]) {
    const own = await send(h.api.item, { method: 'PUT', headers: bearer(h.users.A), query: { id: aId }, body: { title: '바뀐 제목', body: 'b', ...claim } });
    assert.equal(own.statusCode, 403, JSON.stringify(Object.keys(claim)));
    assert.deepEqual(own.body, { error: 'owner_change_forbidden' });
    const other = await send(h.api.item, { method: 'PUT', headers: bearer(h.users.B), query: { id: aId }, body: { title: '탈취', body: 'b', owner_id: h.users.A.sub } });
    assert.equal(other.statusCode, 403);
  }
  assert.equal(snapshot(h), before, '소유자 변경 시도가 자료를 바꾸면 안 됩니다');
  assert.equal(h.memory.rows.get(aId).owner_id, h.users.A.sub);
  const same = await send(h.api.item, { method: 'PUT', headers: bearer(h.users.A), query: { id: aId }, body: { title: '내 ID는 괜찮음', body: 'b', owner_id: h.users.A.sub.toUpperCase() } });
  assert.equal(same.statusCode, 200);
  assert.equal(h.memory.rows.get(aId).owner_id, h.users.A.sub);
});

test('a body owner_id never decides who owns a new note, and a taken id is not overwritten', async () => {
  const { h, aId } = await twoUsers();
  const forged = await send(h.api.collection, { method: 'POST', headers: bearer(h.users.B), body: { title: 't', body: 'b', owner_id: h.users.A.sub, ownerId: h.users.A.sub } });
  assert.equal(forged.statusCode, 201);
  assert.equal(h.memory.rows.get(forged.body.id).owner_id, h.users.B.sub, '확인된 사용자 ID로 저장해야 합니다');
  const before = snapshot(h);
  const clash = await send(h.api.collection, { method: 'POST', headers: bearer(h.users.B), body: { id: aId, title: '덮어쓰기', body: 'x' } });
  assert.equal(clash.statusCode, 409);
  assert.equal(snapshot(h), before);
});

test('the handler alone keeps users apart even if the store forgets the owner filter', async () => {
  const { h, aId, bId } = await twoUsers({ filterOwner: false });
  const before = snapshot(h);
  for (const [user, id] of [[h.users.B, aId], [h.users.A, bId]]) {
    for (const method of ['GET', 'PUT', 'DELETE']) {
      const res = await send(h.api.item, { method, headers: bearer(user), query: { id }, body: method === 'PUT' ? { title: 'x', body: 'y' } : undefined });
      assert.equal(res.statusCode, 404, `${method}`);
    }
  }
  assert.equal(snapshot(h), before);
});

test('an unfiltered owner mismatch from the store is never reported as success', async () => {
  const seen = [];
  const store = {
    async get() { return { id: IDS.other, title: 't', body: 'b', ownerId: randomUUID() }; },
    async update() { seen.push('update'); return true; }, async remove() { seen.push('remove'); return true; },
  };
  const h = apiHarness({ createStore: () => store });
  for (const method of ['GET', 'PUT', 'DELETE']) {
    const res = await send(h.api.item, { method, headers: bearer(h.users.A), query: { id: IDS.other }, body: { title: 't', body: 'b' } });
    assert.equal(res.statusCode, 404, method);
  }
  assert.deepEqual(seen, [], '남의 메모에는 쓰기·삭제를 보내면 안 됩니다');
});

test('a verified judge identity (a) is accepted and a wrong audience is not', async () => {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const sign = (audience, sub) => new SignJWT({ aleph_run: randomUUID(), aleph_role: 'judge', aleph_identity: 'a' })
    .setProtectedHeader({ alg: 'ES256' }).setIssuer(realConfig.judgeIssuer).setAudience(audience)
    .setSubject(sub).setIssuedAt().setExpirationTime('10m').sign(privateKey);
  const audience = new URL(realConfig.publicAppUrl).hostname;
  const h = apiHarness({ judgeKeySet: async () => publicKey });
  const sub = randomUUID();
  const ok = await send(h.api.collection, { method: 'POST', headers: { authorization: `Bearer ${await sign(audience, sub)}` }, body: { title: 't', body: 'b' } });
  assert.equal(ok.statusCode, 201);
  assert.equal(h.memory.rows.get(ok.body.id).owner_id, sub);
  const wrong = await send(h.api.collection, { headers: { authorization: `Bearer ${await sign('other.example.test', randomUUID())}` } });
  assert.equal(wrong.statusCode, 401);
});

test('failures close the door: no config, no server key, store errors and crashes give no data or secrets', async () => {
  const logs = [];
  const mk = (extra) => createNotesApi({ env: goodEnv, log: (m) => logs.push(m), loadConfig: () => realConfig,
    createVerifier: () => async () => ({ kind: 'student', userId: randomUUID() }), createClient: () => ({}), ...extra });
  const unconfigured = await send(mk({ loadConfig: () => { throw new Error('no config'); } }).collection, { headers: { authorization: 'Bearer a.b.c' } });
  assert.deepEqual([unconfigured.statusCode, unconfigured.body], [500, { error: 'login_not_configured' }]);
  const noKey = await send(mk({ env: { SUPABASE_URL: goodEnv.SUPABASE_URL } }).collection, { headers: { authorization: 'Bearer a.b.c' } });
  assert.equal(noKey.statusCode, 500);
  const throwing = await send(mk({ createVerifier: () => async () => { throw new Error('verifier down'); } }).collection, { headers: { authorization: 'Bearer a.b.c' } });
  assert.equal(throwing.statusCode, 401);
  const storeFails = await send(mk({ createStore: () => ({ list: async () => { throw new NotesStoreError({ code: '42501', message: `denied ${FAKE_KEY}` }); } }) }).collection,
    { headers: { authorization: 'Bearer a.b.c' } });
  assert.deepEqual([storeFails.statusCode, storeFails.body], [502, { error: 'upstream_error' }]);
  const crashes = await send(mk({ createStore: () => ({ list: async () => { throw new Error(`boom ${FAKE_KEY}`); } }) }).collection,
    { headers: { authorization: 'Bearer a.b.c' } });
  assert.deepEqual([crashes.statusCode, crashes.body], [500, { error: 'server_error' }]);
  const everything = JSON.stringify([logs, storeFails.body, crashes.body]);
  assert.ok(!everything.includes(FAKE_KEY) && !everything.includes('boom') && !everything.includes('denied') && !everything.includes('verifier down'));
  assert.ok(logs.some((line) => line.includes('42501')), '오류 코드는 로그에 남아야 합니다');
});

test('tokens never appear in responses or logs', async () => {
  const h = apiHarness();
  const id = await add(h, h.users.A, { title: 't', body: 'b' });
  const responses = [
    await send(h.api.collection, { headers: bearer(h.users.A) }),
    await send(h.api.item, { headers: bearer(h.users.A), query: { id } }),
    await send(h.api.item, { method: 'DELETE', headers: bearer(h.users.A), query: { id: IDS.missing } }),
    await send(h.api.collection, { headers: { authorization: `Bearer ${h.users.A.token}x` } }),
  ];
  const everything = JSON.stringify([responses.map((r) => [r.body, r.headers]), h.seen.logs]);
  assert.ok(!everything.includes(h.users.A.token) && !everything.includes(FAKE_KEY));
});

test('the notes store maps body to content and stores only title, content, id and owner_id', async () => {
  const calls = [];
  const chain = (result) => {
    const obj = {};
    for (const name of ['select', 'eq', 'order', 'insert', 'update', 'delete', 'maybeSingle', 'single']) {
      obj[name] = (...args) => { calls.push([name, ...args]); return obj; };
    }
    obj.then = (resolve, reject) => Promise.resolve(result).then(resolve, reject);
    return obj;
  };
  let next;
  const store = createNotesStore({ from: (table) => { calls.push(['from', table]); return chain(next); } });
  const owner = randomUUID();
  const noteId = randomUUID();

  next = { data: [{ id: noteId, title: 'T', content: 'C' }], error: null };
  assert.deepEqual(await store.list(owner), [{ id: noteId, title: 'T', body: 'C' }]);
  assert.deepEqual(calls.filter(([name]) => name === 'eq'), [['eq', 'owner_id', owner]]);
  calls.length = 0;

  next = { data: { id: noteId }, error: null };
  assert.equal(await store.create({ id: noteId, ownerId: owner, title: 'T', body: 'C' }), noteId);
  assert.deepEqual(calls.find(([name]) => name === 'insert'), ['insert', { id: noteId, owner_id: owner, title: 'T', content: 'C' }]);
  calls.length = 0;

  next = { data: { id: noteId, title: 'T', content: 'C', owner_id: owner }, error: null };
  assert.deepEqual(await store.get(noteId), { id: noteId, title: 'T', body: 'C', ownerId: owner });
  assert.deepEqual(calls.find(([name]) => name === 'select'), ['select', 'id, title, content, owner_id']);
  calls.length = 0;

  next = { data: [{ id: noteId }], error: null };
  assert.equal(await store.update(noteId, owner, { title: 'N', body: 'M' }), true);
  assert.deepEqual(calls.find(([name]) => name === 'update'), ['update', { title: 'N', content: 'M' }], 'owner_id는 수정 값에 없어야 합니다');
  assert.deepEqual(calls.filter(([name]) => name === 'eq'), [['eq', 'id', noteId], ['eq', 'owner_id', owner]]);
  calls.length = 0;
  next = { data: [], error: null };
  assert.equal(await store.update(noteId, owner, { title: 'N', body: 'M' }), false);
  calls.length = 0;
  assert.equal(await store.remove(noteId, owner), false);
  assert.deepEqual(calls.filter(([name]) => name === 'eq'), [['eq', 'id', noteId], ['eq', 'owner_id', owner]], '삭제에도 소유자 조건이 붙어야 합니다');
  next = { data: null, error: null };
  assert.equal(await store.get(noteId), null);

  next = { data: null, error: { code: '42501', message: `denied for ${FAKE_KEY}` } };
  await assert.rejects(() => store.list(owner), (error) => error instanceof NotesStoreError && error.code === '42501'
    && !error.message.includes(FAKE_KEY));
});

test('the screen sends only the SDK token, never builds identity itself, and the page script parses', () => {
  const page = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.ok(page.includes('Authorization: `Bearer ${session.access_token}`'));
  assert.ok(page.includes("method: 'POST'") && page.includes("method: 'PUT'") && page.includes("method: 'DELETE'"));
  assert.ok(!/userId|x-user|x-role|role:|owner_id|innerHTML|localStorage/u.test(page));
  const script = /<script type="module">([\s\S]*?)<\/script>/u.exec(page)[1];
  const dir = mkdtempSync(join(tmpdir(), 'page-'));
  writeFileSync(join(dir, 'page.mjs'), script);
  assert.doesNotThrow(() => execFileSync(process.execPath, ['--check', join(dir, 'page.mjs')], { stdio: 'pipe' }));
});

test('the handler trusts only the unmodified helper result', () => {
  const handler = readFileSync(new URL('../src/notes-handler.mjs', import.meta.url), 'utf8');
  assert.ok(handler.includes("from './verify-login.mjs'") && handler.includes('ownerId: userId'));
  assert.ok(!/jwtVerify|decodeJwt|getClaims|createRemoteJWKSet/u.test(handler), '토큰 검사는 도우미가 하고 여기서 새로 만들지 않습니다');
  assert.ok(!/(ownerId|userId|owner_id|role)\s*[:=]\s*(input|req)\b/u.test(handler), '브라우저가 보낸 값으로 사용자나 소유자를 정하면 안 됩니다');
  assert.ok(!/req\.(query|body)\.(owner_id|ownerId|userId|role)|headers\??\.\[?['"]?x-/u.test(handler));
  assert.ok(/ownerId: userId/u.test(handler) && /notes\.update\(id, userId/u.test(handler) && /notes\.remove\(id, userId/u.test(handler),
    '추가·수정·삭제에는 검증된 사용자 ID를 넘겨야 합니다');
});

test('a restored login after reload no longer says the user is logged out', async () => {
  const panel = fakePanel();
  const listeners = [];
  const sdk = { createClient: () => ({ auth: {
    onAuthStateChange(callback) { listeners.push(callback); return { data: { subscription: {} } }; },
    getSession: async () => ({ data: { session: { user: { email: 'tester@example.test' } } } }),
    signInWithPassword: async () => ({ error: null }), signOut: async () => ({ error: null }),
  } }) };
  mountAuthPanel({ root: panel.root, config: goodAuth, sdk });
  assert.equal(panel.els.message.textContent, '로그인하지 않았습니다.');
  listeners.forEach((callback) => callback('INITIAL_SESSION', { user: { email: 'tester@example.test' } }));
  assert.equal(panel.body.dataset.auth, 'in');
  assert.equal(panel.els.message.textContent, '로그인한 상태입니다.');
  assert.equal(panel.els.badge.textContent, '로그인 상태');
  // 세션이 없는 복원은 로그아웃 문구를 그대로 둔다.
  const out = fakePanel();
  const outListeners = [];
  mountAuthPanel({ root: out.root, config: goodAuth, sdk: { createClient: () => ({ auth: {
    onAuthStateChange(callback) { outListeners.push(callback); return { data: { subscription: {} } }; },
    getSession: async () => ({ data: { session: null } }),
  } }) } });
  outListeners.forEach((callback) => callback('INITIAL_SESSION', null));
  assert.equal(out.els.message.textContent, '로그인하지 않았습니다.');
});

// ---- 3단계 저장점: 공격 점검이 실제 요청 결과만 기록한다 ----
const step3 = { ...config, step: 3, identityProvider: { issuer: 'https://abcdefghij.supabase.co/auth/v1' } };

function serverFetch({ guarded = true, leakKey = false, denyHeader = false, sawToken } = {}) {
  const requests = [];
  const impl = async (url, init = {}) => {
    const u = new URL(String(url));
    const method = init.method ?? 'GET';
    const headers = init.headers ?? {};
    requests.push({ method, path: u.pathname, authorization: headers.authorization, role: headers['x-role'] });
    if (denyHeader) return new Response('blocked', { status: 403, headers: { 'x-deny-reason': 'host_not_allowed' } });
    if (u.pathname === '/data.json') return new Response(JSON.stringify({ notes: [] }), { status: 200 });
    const good = headers.authorization === 'Bearer REAL-LOGIN-TOKEN';
    if (good) { sawToken?.(); return new Response(JSON.stringify([{ id: 'x', title: 'SECRET_TITLE_VALUE', body: 'SECRET_BODY_VALUE' }]), { status: 200 }); }
    if (!guarded) return new Response(JSON.stringify([{ id: 'x', title: 'SECRET_TITLE_VALUE', body: 'SECRET_BODY_VALUE' }]), { status: 200 });
    return new Response(JSON.stringify({ error: 'unauthorized', ...(leakKey ? { leak: FAKE_KEY } : {}) }), { status: 401 });
  };
  return { requests, impl };
}
async function withFetch(impl, run) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  try { return await run(); } finally { globalThis.fetch = original; }
}

test('step 3 attack check sends the real refused requests and records only what came back', async () => {
  const { requests, impl } = serverFetch();
  const previous = process.env.ATTACK_CHECK_TOKEN;
  delete process.env.ATTACK_CHECK_TOKEN;
  try {
    const results = await withFetch(impl, () => runAttackChecks(step3));
    const byId = Object.fromEntries(results.map((item) => [item.attackId, item]));
    assert.deepEqual(Object.keys(byId).sort(), ['anonymous_create', 'anonymous_delete', 'anonymous_item_read', 'anonymous_list_read',
      'anonymous_update', 'api_key_not_exposed', 'forged_login_rejected', 'normal_login_read', 'static_data_json_read']);
    for (const id of ['anonymous_create', 'anonymous_delete', 'anonymous_item_read', 'anonymous_list_read', 'anonymous_update', 'forged_login_rejected']) {
      assert.match(byId[id].observed, /메모 내용 없이 거부됨 \(HTTP 401, 응답 코드 unauthorized\)/u, id);
    }
    assert.match(byId.static_data_json_read.observed, /보이지 않음 \(HTTP 200\)/u);
    assert.match(byId.api_key_not_exposed.observed, /값이 없음/u);
    assert.match(byId.normal_login_read.observed, /^미실행/u, '토큰 없이는 정상 요청을 보냈다고 쓰면 안 됩니다');
    const sent = requests.map((item) => `${item.method} ${item.path.replace(/[0-9a-f-]{36}/u, ':id')}`);
    for (const route of ['GET /api/notes', 'POST /api/notes', 'GET /api/notes/:id', 'PUT /api/notes/:id', 'DELETE /api/notes/:id']) {
      assert.ok(sent.includes(route), `${route} 요청을 실제로 보내야 합니다`);
    }
    const forged = requests.find((item) => item.role === 'admin');
    assert.ok(forged && forged.authorization.startsWith('Bearer '));
    assert.ok(!JSON.stringify(results).includes(forged.authorization), '가짜 토큰도 결과에 적으면 안 됩니다');
    for (const item of results) assert.ok(item.expected.length <= 300 && item.observed.length <= 300);
  } finally {
    if (previous !== undefined) process.env.ATTACK_CHECK_TOKEN = previous;
  }
});

test('step 3 attack check reports a real hole, an unreachable server and a normal login honestly', async () => {
  const hole = await withFetch(serverFetch({ guarded: false }).impl, () => runAttackChecks(step3));
  assert.ok(hole.some((item) => /메모 내용이 응답됨/u.test(item.observed)), '막히지 않았다면 그대로 적어야 합니다');
  assert.ok(!JSON.stringify(hole).includes('SECRET_TITLE_VALUE') && !JSON.stringify(hole).includes('SECRET_BODY_VALUE'));

  const leak = await withFetch(serverFetch({ leakKey: true }).impl, () => runAttackChecks(step3));
  assert.match(leak.find((item) => item.attackId === 'api_key_not_exposed').observed, /키로 보이는 값이 있음/u);
  assert.ok(!JSON.stringify(leak).includes(FAKE_KEY));

  const blocked = await withFetch(serverFetch({ denyHeader: true }).impl, () => runAttackChecks(step3));
  assert.ok(blocked.every((item) => /^미실행/u.test(item.observed)), '서버에 닿지 못했다면 점검했다고 쓰면 안 됩니다');
  const down = await withFetch(async () => { throw Object.assign(new Error('boom'), { name: 'TypeError' }); }, () => runAttackChecks(step3));
  assert.ok(down.every((item) => /^미실행/u.test(item.observed)));

  const previous = process.env.ATTACK_CHECK_TOKEN;
  process.env.ATTACK_CHECK_TOKEN = 'REAL-LOGIN-TOKEN';
  try {
    const normal = await withFetch(serverFetch().impl, () => runAttackChecks(step3));
    const item = normal.find((entry) => entry.attackId === 'normal_login_read');
    assert.match(item.observed, /HTTP 200로 메모 1건이 배열로 응답됨/u);
    assert.ok(!JSON.stringify(normal).includes('REAL-LOGIN-TOKEN') && !JSON.stringify(normal).includes('SECRET_TITLE_VALUE'));
  } finally {
    if (previous === undefined) delete process.env.ATTACK_CHECK_TOKEN; else process.env.ATTACK_CHECK_TOKEN = previous;
  }
});

test('the saved config matches the stage 4 implementation', () => {
  assert.equal(realConfig.step, 4);
  assert.equal(realConfig.repoUrl, 'https://github.com/reereez15/choi-bujang-secret-vault');
  assert.equal(realConfig.publicAppUrl, 'https://choi-bujang-secret-vault-qkh6.vercel.app');
  assert.equal(realConfig.originalApiUrl, null);
  assert.equal(realConfig.restoreRoute, null);
  assert.ok(realConfig.judgeIssuer.endsWith('/defense/judge'));
});

// ---- 4단계 저장점: 상대 메모 접근·소유자 변경 점검 ----
const step4 = { ...step3, step: 4 };
const OWNER_IDS = ['owner_cross_read', 'owner_cross_update', 'owner_cross_delete', 'owner_list_isolation', 'owner_change_rejected', 'owner_note_intact'];

// 토큰으로 사용자를 구분하는 가짜 서버. guarded=false이면 소유자를 확인하지 않는 서버처럼 동작한다.
function ownerServer({ guarded = true, createStatus } = {}) {
  const notes = new Map();
  const requests = [];
  const owners = { 'Bearer TOKEN-A': 'A', 'Bearer TOKEN-B': 'B' };
  const reply = (status, body) => new Response(JSON.stringify(body), { status });
  const impl = async (url, init = {}) => {
    const u = new URL(String(url));
    const method = init.method ?? 'GET';
    const headers = init.headers ?? {};
    const me = owners[headers.authorization];
    requests.push({ method, path: u.pathname, me });
    if (u.pathname === '/data.json') return reply(200, { notes: [] });
    if (!me) return reply(401, { error: 'unauthorized' });
    const body = init.body ? JSON.parse(init.body) : {};
    if (u.pathname === '/api/notes') {
      if (method === 'POST') {
        if (createStatus) return reply(createStatus, { error: 'x' });
        notes.set(body.id, { id: body.id, title: body.title, body: body.body, owner: me });
        return reply(201, { id: body.id });
      }
      return reply(200, [...notes.values()].filter((n) => n.owner === me).map(({ id, title, body: b }) => ({ id, title, body: b })));
    }
    const id = u.pathname.split('/').pop();
    const note = notes.get(id);
    if (!note || (guarded && note.owner !== me)) return reply(404, { error: 'not_found' });
    if (method === 'GET') return reply(200, { id, title: note.title, body: note.body });
    if (method === 'PUT') {
      if (body.owner_id !== undefined && guarded && body.owner_id !== me) return reply(403, { error: 'owner_change_forbidden' });
      Object.assign(note, { title: body.title, body: body.body });
      return reply(200, { id });
    }
    notes.delete(id);
    return reply(200, { id });
  };
  return { notes, requests, impl };
}
async function withTokens(a, b, run) {
  const saved = [process.env.ATTACK_CHECK_TOKEN, process.env.ATTACK_CHECK_TOKEN_B];
  for (const [name, value] of [['ATTACK_CHECK_TOKEN', a], ['ATTACK_CHECK_TOKEN_B', b]]) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
  try { return await run(); } finally {
    for (const [name, value] of [['ATTACK_CHECK_TOKEN', saved[0]], ['ATTACK_CHECK_TOKEN_B', saved[1]]]) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
}
const byId = (results) => Object.fromEntries(results.map((item) => [item.attackId, item]));

test('step 4 attack check sends the real cross-user requests and cleans up its temporary note', async () => {
  const server = ownerServer();
  const results = await withTokens('TOKEN-A', 'TOKEN-B', () => withFetch(server.impl, () => runAttackChecks(step4)));
  const items = byId(results);
  assert.equal(results.length, 15);
  assert.equal(new Set(results.map((item) => item.attackId)).size, 15);
  for (const id of OWNER_IDS) assert.ok(items[id], id);
  for (const id of ['owner_cross_read', 'owner_cross_update', 'owner_cross_delete']) {
    assert.match(items[id].observed, /^거부됨 \(HTTP 404, 응답 코드 not_found\)$/u, id);
  }
  assert.match(items.owner_change_rejected.observed, /^거부됨 \(HTTP 403, 응답 코드 owner_change_forbidden\)$/u);
  assert.match(items.owner_list_isolation.observed, /목록에 A의 메모가 없음 \(HTTP 200, 메모 0건\)/u);
  assert.match(items.owner_note_intact.observed, /원래 제목 그대로 읽음 \(HTTP 200\)/u);
  assert.match(items.normal_login_read.observed, /HTTP 200로 메모/u);
  assert.equal(server.notes.size, 0, '점검이 만든 임시 메모는 지워야 합니다');
  const crossCalls = server.requests.filter((item) => item.me === 'B').map((item) => item.method);
  assert.deepEqual(crossCalls, ['GET', 'PUT', 'DELETE', 'GET']);
  for (const item of results) assert.ok(item.expected.length <= 300 && item.observed.length <= 300);
  assert.ok(!JSON.stringify(results).includes('TOKEN-A') && !JSON.stringify(results).includes('TOKEN-B'));
});

test('step 4 attack check reports a real ownership hole instead of hiding it', async () => {
  const server = ownerServer({ guarded: false });
  const results = await withTokens('TOKEN-A', 'TOKEN-B', () => withFetch(server.impl, () => runAttackChecks(step4)));
  const items = byId(results);
  for (const id of ['owner_cross_read', 'owner_cross_update', 'owner_cross_delete', 'owner_change_rejected']) {
    assert.match(items[id].observed, /^거부되지 않음/u, id);
  }
  assert.match(items.owner_cross_read.observed, /메모 내용이 응답됨/u);
  assert.match(items.owner_note_intact.observed, /바뀌었거나 읽히지 않음/u, '남이 지운 뒤라면 A의 메모가 없다고 적어야 합니다');
  assert.equal(server.notes.size, 0);
});

test('step 4 attack check does not claim owner checks without two distinct real tokens', async () => {
  for (const [a, b, why] of [[undefined, undefined, /토큰이 필요/u], ['TOKEN-A', undefined, /토큰이 필요/u], ['TOKEN-A', 'TOKEN-A', /같아서/u]]) {
    const server = ownerServer();
    const results = await withTokens(a, b, () => withFetch(server.impl, () => runAttackChecks(step4)));
    const items = byId(results);
    for (const id of OWNER_IDS) assert.match(items[id].observed, /^미실행/u, id);
    assert.match(items.owner_cross_read.observed, why);
    assert.ok(!server.requests.some((item) => item.method === 'POST' && item.me), '토큰이 없으면 로그인한 메모 추가를 보내면 안 됩니다');
  }
  const failedCreate = ownerServer({ createStatus: 401 });
  const results = await withTokens('TOKEN-A', 'TOKEN-B', () => withFetch(failedCreate.impl, () => runAttackChecks(step4)));
  for (const id of OWNER_IDS) assert.match(byId(results)[id].observed, /^미실행: A의 임시 메모를 만들지 못했습니다 \(HTTP 401\)/u);
  const blocked = await withTokens('TOKEN-A', 'TOKEN-B', () => withFetch(serverFetch({ denyHeader: true }).impl, () => runAttackChecks(step4)));
  assert.ok(blocked.every((item) => /^미실행/u.test(item.observed)), '서버에 닿지 못했다면 모두 미실행이어야 합니다');
});

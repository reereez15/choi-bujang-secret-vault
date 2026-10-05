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
  assert.throws(() => deploymentIdentity(env, { ...config, step: 4 }));
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

// 로그인한 사용자 두 명(A, B)과 메모리 안의 가짜 자료 저장소
function memoryStore() {
  const rows = new Map();
  const calls = [];
  const view = ({ id, title, body }) => ({ id, title, body });
  return { rows, calls, store: {
    async list(ownerId) { calls.push('list'); return [...rows.values()].filter((row) => row.owner_id === ownerId).map(view); },
    async get(id) { calls.push('get'); return rows.has(id) ? view(rows.get(id)) : null; },
    async create({ id, ownerId, title, body }) {
      calls.push('create');
      if (rows.has(id)) throw new NotesStoreError({ code: '23505' });
      rows.set(id, { id, owner_id: ownerId, title, body });
      return id;
    },
    async update(id, { title, body }) {
      calls.push('update');
      if (!rows.has(id)) return false;
      Object.assign(rows.get(id), { title, body });
      return true;
    },
    async remove(id) { calls.push('remove'); return rows.delete(id); },
  } };
}

function apiHarness({ judgeKeySet = noJudgeKeys, createStore, extra = {} } = {}) {
  const users = {
    A: { sub: randomUUID(), token: null },
    B: { sub: randomUUID(), token: null },
  };
  for (const user of Object.values(users)) user.token = unsignedToken({ iss: studentIssuer, sub: user.sub, n: randomUUID() });
  const claimsByToken = new Map(Object.values(users).map((user) => [user.token, studentClaims(user.sub)]));
  const memory = memoryStore();
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

  const put = await send(h.api.item, { method: 'PUT', headers: bearer(h.users.A), query: { id }, body: { title: '바뀐 제목', body: '바뀐 내용', owner_id: h.users.B.sub } });
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

// 알려진 약점: 4단계에서 소유자 검사를 붙이면 이 시험은 "B는 접근할 수 없다"로 바꿔야 한다.
test('KNOWN GAP (step 4): a different logged-in user can still read, edit and delete A\'s note by id', async () => {
  const h = apiHarness();
  const id = await add(h, h.users.A, { title: 'A의 메모', body: 'A만 봐야 하는 내용' });
  assert.equal((await send(h.api.item, { headers: bearer(h.users.B), query: { id } })).statusCode, 200);
  assert.equal((await send(h.api.item, { method: 'PUT', headers: bearer(h.users.B), query: { id }, body: { title: 'B가 고침', body: 'x' } })).statusCode, 200);
  assert.equal(h.memory.rows.get(id).title, 'B가 고침');
  assert.equal((await send(h.api.item, { method: 'DELETE', headers: bearer(h.users.B), query: { id } })).statusCode, 200);
  assert.equal(h.memory.rows.has(id), false);
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

  next = { data: [{ id: noteId }], error: null };
  assert.equal(await store.update(noteId, { title: 'N', body: 'M' }), true);
  assert.deepEqual(calls.find(([name]) => name === 'update'), ['update', { title: 'N', content: 'M' }]);
  assert.deepEqual(calls.find(([name]) => name === 'eq'), ['eq', 'id', noteId]);
  next = { data: [], error: null };
  assert.equal(await store.update(noteId, { title: 'N', body: 'M' }), false);
  assert.equal(await store.remove(noteId), false);
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
  assert.ok(!/input\.(owner_id|ownerId|userId|role)|req\.(query|body)\.(owner_id|ownerId|userId|role)|headers\??\.\[?['"]?x-/u.test(handler),
    '브라우저가 보낸 사용자 값은 읽지 않습니다');
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

test('the saved config matches the stage 3 implementation', () => {
  assert.equal(realConfig.step, 3);
  assert.equal(realConfig.repoUrl, 'https://github.com/reereez15/choi-bujang-secret-vault');
  assert.equal(realConfig.publicAppUrl, 'https://choi-bujang-secret-vault-qkh6.vercel.app');
  assert.equal(realConfig.originalApiUrl, null);
  assert.equal(realConfig.restoreRoute, null);
  assert.ok(realConfig.judgeIssuer.endsWith('/defense/judge'));
});

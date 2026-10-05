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
import { createNotesHandler } from '../src/notes-handler.mjs';

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
const fakeClient = (result) => () => ({
  from: () => ({ select: () => ({ order: () => ({ order: async () => result }) }) }),
});

test('step 2 build identity records the step and still rejects bad input', () => {
  assert.equal(deploymentIdentity(env, step2).step, 2);
  assert.throws(() => deploymentIdentity(env, { ...config, step: 3 }));
});

test('notes function returns only title and content from the server', async () => {
  let clientArgs;
  const handler = createNotesHandler({
    env: goodEnv, log: () => {},
    createClient: (...args) => {
      clientArgs = args;
      return fakeClient({ data: [{ title: '제목', content: '내용', owner_id: 'x', id: 'y' }], error: null })();
    },
  });
  const res = fakeRes();
  await handler({ method: 'GET' }, res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body, { notes: [{ title: '제목', content: '내용' }] });
  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.equal(clientArgs[0], goodEnv.SUPABASE_URL);
  assert.equal(clientArgs[1], FAKE_KEY);
  assert.equal(clientArgs[2].auth.persistSession, false);
});

test('notes function refuses other methods and a missing server configuration', async () => {
  const logs = [];
  const handler = createNotesHandler({ env: {}, log: (message) => logs.push(message) });
  const post = fakeRes();
  await handler({ method: 'POST' }, post);
  assert.equal(post.statusCode, 405);
  assert.equal(post.headers.Allow, 'GET');
  const missing = fakeRes();
  await handler({ method: 'GET' }, missing);
  assert.equal(missing.statusCode, 500);
  assert.deepEqual(missing.body, { error: 'server_not_configured' });
  assert.ok(!JSON.stringify([missing.body, logs]).includes('SUPABASE_SECRET_KEY'));
});

test('notes function never puts the key in a response or a log', async () => {
  const logs = [];
  const failing = createNotesHandler({
    env: goodEnv, log: (message) => logs.push(message),
    createClient: fakeClient({ data: null, error: { code: '42501', message: `denied for ${FAKE_KEY}` } }),
  });
  const upstream = fakeRes();
  await failing({ method: 'GET' }, upstream);
  assert.equal(upstream.statusCode, 502);
  const throwing = createNotesHandler({
    env: goodEnv, log: (message) => logs.push(message),
    createClient: () => { throw new Error(`bad key ${FAKE_KEY}`); },
  });
  const thrown = fakeRes();
  await throwing({ method: 'GET' }, thrown);
  assert.equal(thrown.statusCode, 500);
  const everything = JSON.stringify([upstream.body, thrown.body, upstream.headers, thrown.headers, logs]);
  assert.ok(!everything.includes(FAKE_KEY));
  assert.ok(!everything.includes('bad key'));
});

test('screen reads the server function and the public files hold no notes', () => {
  const page = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.ok(page.includes("fetch('/api/notes'"));
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

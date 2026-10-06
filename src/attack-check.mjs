import { randomUUID } from 'node:crypto';

// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
const KEY_SHAPE = /\bsb_secret_[A-Za-z0-9_-]{8,}|SUPABASE_SECRET_KEY|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/u;

function publicApp(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  return app;
}

const request = (app, path, { method = 'GET', headers, body } = {}) => fetch(new URL(path, app), {
  method, headers, body, redirect: 'error', signal: AbortSignal.timeout(10000),
});

async function readBody(response) {
  const text = await response.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* 비JSON 응답은 점검 실패로 본다. */ }
  return { text, data };
}

// 요청을 보내고 결과만 돌려준다. 배포 서버에 닿지 못했거나 중간 차단 장치가 대신 답했다면 점검한 것으로 세지 않는다.
async function attempt(app, path, options) {
  let response;
  try {
    response = await request(app, path, options);
  } catch (error) {
    return { unreached: `요청이 배포 서버에 닿지 못했습니다 (${String(error?.name ?? 'Error').slice(0, 40)})` };
  }
  if (response.headers.has('x-deny-reason')) {
    return { unreached: '중간 차단 장치가 대신 답해서 배포 서버가 응답하지 않았습니다' };
  }
  const { text, data } = await readBody(response);
  const headerText = [...response.headers].map(([name, value]) => `${name}: ${value}`).join('\n');
  return { response, text, data, headerText };
}
const notReached = (result) => `미실행: ${result.unreached}.`;
const noteCount = (data) => (Array.isArray(data) ? data.length
  : Array.isArray(data?.notes) ? data.notes.length : 0);

async function runStepThree(config, app) {
  const attempts = [];
  const randomId = randomUUID();
  const refused = (id, expected, path, options) => attempts.push((async () => {
    const result = await attempt(app, path, options);
    if (result.unreached) return { attackId: id, expected, observed: notReached(result) };
    const { response, data } = result;
    const leaked = noteCount(data) > 0 || Array.isArray(data) || typeof data?.title === 'string';
    const code = typeof data?.error === 'string' && /^[a-z_]{1,40}$/u.test(data.error) ? `, 응답 코드 ${data.error}` : '';
    return { attackId: id, expected,
      observed: `${leaked ? '메모 내용이 응답됨' : '메모 내용 없이 거부됨'} (HTTP ${response.status}${code})` };
  })());
  const json = { 'content-type': 'application/json' };

  refused('anonymous_list_read', '로그인 없이 GET /api/notes를 부르면 자료 없이 401로 거부됨', '/api/notes');
  refused('anonymous_create', '로그인 없이 POST /api/notes를 부르면 만들지 않고 401로 거부됨', '/api/notes',
    { method: 'POST', headers: json, body: '{}' });
  refused('anonymous_item_read', '로그인 없이 GET /api/notes/:id를 부르면 자료 없이 401로 거부됨', `/api/notes/${randomId}`);
  refused('anonymous_update', '로그인 없이 PUT /api/notes/:id를 부르면 고치지 않고 401로 거부됨', `/api/notes/${randomId}`,
    { method: 'PUT', headers: json, body: '{}' });
  refused('anonymous_delete', '로그인 없이 DELETE /api/notes/:id를 부르면 지우지 않고 401로 거부됨', `/api/notes/${randomId}`,
    { method: 'DELETE' });

  // 서명되지 않은 가짜 토큰과 role=admin 같은 위조 값. 검사하는 쪽이 발급자에게 물어 거부해야 한다.
  const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const forged = `${b64({ alg: 'ES256', typ: 'JWT' })}.${b64({ iss: config.identityProvider?.issuer ?? 'forged',
    sub: randomUUID(), aud: 'authenticated', role: 'authenticated', exp: Math.floor(Date.now() / 1000) + 600 })}.c2ln`;
  refused('forged_login_rejected', '위조한 토큰과 role=admin·사용자 번호 값을 보내면 자료 없이 401로 거부됨', '/api/notes',
    { headers: { authorization: `Bearer ${forged}`, 'x-role': 'admin', 'x-user-id': randomUUID() } });

  const results = await Promise.all(attempts);
  const staticResult = await attempt(app, '/data.json');
  if (staticResult.unreached) {
    results.push({ attackId: 'static_data_json_read', expected: '공개 /data.json에 가상 메모가 보이지 않음', observed: notReached(staticResult) });
  } else {
    const { data, response } = staticResult;
    const visible = data?.sampleMarker === config.sampleMarker || noteCount(data) > 0;
    results.push({ attackId: 'static_data_json_read', expected: '공개 /data.json에 가상 메모가 보이지 않음',
      observed: visible ? '비로그인 요청에서 /data.json에 가상 메모가 보임'
        : `비로그인 요청에서 /data.json에 가상 메모가 보이지 않음 (HTTP ${response.status})` });
  }

  // 위 응답 본문과 헤더에 서버 전용 키로 보이는 값이 있었는지 한 번 더 본다.
  const probe = await attempt(app, '/api/notes');
  results.push({ attackId: 'api_key_not_exposed', expected: '/api/notes 응답 본문과 헤더에 서버 전용 키로 보이는 값이 없음',
    observed: probe.unreached ? notReached(probe)
      : (KEY_SHAPE.test(probe.text) || KEY_SHAPE.test(probe.headerText))
        ? '응답 본문 또는 헤더에 키로 보이는 값이 있음' : '응답 본문과 헤더에 키로 보이는 값이 없음' });

  // 정상 로그인 요청은 실제 토큰이 있어야 보낼 수 있다. 토큰은 환경변수로만 받고 어디에도 적지 않는다.
  const token = process.env.ATTACK_CHECK_TOKEN;
  const normalExpected = '정상 로그인 토큰으로 GET /api/notes를 부르면 본인 메모 배열이 응답됨';
  if (!token) {
    results.push({ attackId: 'normal_login_read', expected: normalExpected,
      observed: '미실행: 정상 로그인 요청은 실제 토큰이 필요해 보내지 않았습니다 (환경변수 ATTACK_CHECK_TOKEN 없음).' });
  } else {
    const normal = await attempt(app, '/api/notes', { headers: { authorization: `Bearer ${token}` } });
    results.push({ attackId: 'normal_login_read', expected: normalExpected,
      observed: normal.unreached ? notReached(normal)
        : normal.response.ok && Array.isArray(normal.data)
          ? `HTTP ${normal.response.status}로 메모 ${normal.data.length}건이 배열로 응답됨 (본문은 기록하지 않음)`
          : `정상 요청이 받아들여지지 않음 (HTTP ${normal.response.status})` });
  }
  return results;
}

// 4단계: 서로 다른 두 사용자(A, B)의 실제 토큰이 있어야 보낼 수 있다. 토큰은 환경변수로만 받고 어디에도 적지 않는다.
// A가 임시 메모를 만들고, B가 그 메모를 읽고 고치고 지우려 해 본 뒤, A가 메모를 지워 정리한다.
const OWNER_CHECKS = [
  ['owner_cross_read', '다른 로그인 사용자(B)가 A의 메모를 GET /api/notes/:id로 읽으려 하면 404로 거부됨'],
  ['owner_cross_update', 'B가 A의 메모를 PUT /api/notes/:id로 고치려 하면 404로 거부됨'],
  ['owner_cross_delete', 'B가 A의 메모를 DELETE /api/notes/:id로 지우려 하면 404로 거부됨'],
  ['owner_list_isolation', 'B의 GET /api/notes 목록에는 A의 메모가 들어 있지 않음'],
  ['owner_change_rejected', 'A가 자기 메모의 owner_id를 다른 값으로 바꾸려는 PUT은 403으로 거부됨'],
  ['owner_note_intact', '위 시도가 끝난 뒤에도 A는 자기 메모를 원래 제목 그대로 읽을 수 있음'],
];

async function runOwnerChecks(app) {
  const tokenA = process.env.ATTACK_CHECK_TOKEN;
  const tokenB = process.env.ATTACK_CHECK_TOKEN_B;
  const skip = (reason) => OWNER_CHECKS.map(([attackId, expected]) => ({ attackId, expected, observed: `미실행: ${reason}` }));
  if (!tokenA || !tokenB) {
    return skip('서로 다른 두 사용자(A·B)의 실제 토큰이 필요해 보내지 않았습니다 (환경변수 ATTACK_CHECK_TOKEN, ATTACK_CHECK_TOKEN_B 없음).');
  }
  if (tokenA === tokenB) return skip('두 토큰이 같아서 서로 다른 사용자 점검을 할 수 없습니다.');

  const as = (token, extra = {}) => ({ authorization: `Bearer ${token}`, ...extra });
  const json = { 'content-type': 'application/json' };
  const noteId = randomUUID();
  const title = 'attack-check 임시 메모';
  const created = await attempt(app, '/api/notes', { method: 'POST', headers: as(tokenA, json),
    body: JSON.stringify({ id: noteId, title, body: 'owner check' }) });
  if (created.unreached) return skip(`${created.unreached}.`);
  if (created.response.status !== 201) {
    return skip(`A의 임시 메모를 만들지 못했습니다 (HTTP ${created.response.status}). 토큰이 만료됐는지 확인하세요.`);
  }
  const code = (data) => (typeof data?.error === 'string' && /^[a-z_]{1,40}$/u.test(data.error) ? `, 응답 코드 ${data.error}` : '');
  const refusal = (result, want) => {
    if (result.unreached) return notReached(result);
    const leaked = result.data?.title === title || result.data?.body === 'owner check';
    const ok = result.response.status === want && !leaked;
    return `${ok ? '거부됨' : '거부되지 않음'} (HTTP ${result.response.status}${code(result.data)}${leaked ? ', 메모 내용이 응답됨' : ''})`;
  };
  const observed = {};
  try {
    observed.owner_cross_read = refusal(await attempt(app, `/api/notes/${noteId}`, { headers: as(tokenB) }), 404);
    observed.owner_cross_update = refusal(await attempt(app, `/api/notes/${noteId}`, { method: 'PUT', headers: as(tokenB, json),
      body: JSON.stringify({ title: 'attack-check 탈취', body: 'x' }) }), 404);
    observed.owner_cross_delete = refusal(await attempt(app, `/api/notes/${noteId}`, { method: 'DELETE', headers: as(tokenB) }), 404);
    const list = await attempt(app, '/api/notes', { headers: as(tokenB) });
    observed.owner_list_isolation = list.unreached ? notReached(list)
      : list.response.status === 200 && Array.isArray(list.data) && !list.data.some((note) => note?.id === noteId)
        ? `목록에 A의 메모가 없음 (HTTP 200, 메모 ${list.data.length}건)`
        : `목록에 A의 메모가 보이거나 목록을 받지 못함 (HTTP ${list.response.status})`;
    observed.owner_change_rejected = refusal(await attempt(app, `/api/notes/${noteId}`, { method: 'PUT', headers: as(tokenA, json),
      body: JSON.stringify({ title, body: 'owner check', owner_id: randomUUID() }) }), 403);
    const intact = await attempt(app, `/api/notes/${noteId}`, { headers: as(tokenA) });
    observed.owner_note_intact = intact.unreached ? notReached(intact)
      : intact.response.status === 200 && intact.data?.title === title
        ? 'A는 자기 메모를 원래 제목 그대로 읽음 (HTTP 200)'
        : `A의 메모가 바뀌었거나 읽히지 않음 (HTTP ${intact.response.status})`;
  } finally {
    await attempt(app, `/api/notes/${noteId}`, { method: 'DELETE', headers: as(tokenA) });
  }
  return OWNER_CHECKS.map(([attackId, expected]) => ({ attackId, expected, observed: observed[attackId] }));
}

// 5단계: 원본 자료 API(Supabase Data API의 메모 테이블)를 앱 밖에서 직접 부른다. 공개용(anon) 키만 쓰고 서버 전용 키는 쓰지 않는다.
// 쓰기 점검은 데이터가 바뀌지 않게 만든다: 추가는 필수 칸이 빠진 빈 본문이라 허용돼도 저장되지 않고, 수정·삭제는 없는 id만 가리킨다.
const ORIGINAL_CHECKS = [
  ['original_api_anon_read', '로그인 없이(anon 키만) 원본 자료 API를 쿼리 없이 GET으로 부르면 메모 없이 401 또는 403으로 거부됨'],
  ['original_api_anon_insert', 'anon 키로 원본 자료 API에 POST(추가)하면 만들지 않고 401 또는 403으로 거부됨'],
  ['original_api_anon_modify', 'anon 키로 원본 자료 API에 PATCH(수정)와 DELETE(삭제)를 보내면 둘 다 401 또는 403으로 거부됨'],
  ['original_api_user_read', '정상 로그인 토큰(A)을 붙여도 원본 자료 API를 직접 GET으로 부르면 메모 없이 401 또는 403으로 거부됨'],
];

async function runOriginalApiChecks(config) {
  const url = config.originalApiUrl;
  if (typeof url !== 'string' || !url.startsWith('https://')) {
    throw new Error('aleph.config.json의 originalApiUrl에 원본 자료 API의 HTTPS 주소를 넣어 주세요.');
  }
  const original = new URL(url);
  if (original.search || original.hash || original.username || original.password) {
    throw new Error('originalApiUrl은 쿼리·해시·인증 정보가 없는 주소여야 합니다.');
  }
  // 이 저장소와 브라우저 코드에는 Supabase 키가 없다. anon 점검에 쓸 공개용 키는 환경변수로만 받고 어디에도 적지 않는다.
  const key = process.env.ATTACK_CHECK_ANON_KEY;
  const skip = (reason) => ORIGINAL_CHECKS.map(([attackId, expected]) => ({ attackId, expected, observed: `미실행: ${reason}` }));
  if (typeof key !== 'string' || !key.trim()) {
    return skip('anon 점검에 쓸 공개용 키가 필요해 보내지 않았습니다 (환경변수 ATTACK_CHECK_ANON_KEY 없음).');
  }
  if (key.startsWith('sb_secret_')) return skip('서버 전용 키로 보여 보내지 않았습니다. 공개용(publishable) 키를 넣어 주세요.');
  const json = { 'content-type': 'application/json' };
  const verdict = (result) => {
    if (result.unreached) return null;
    const rows = Array.isArray(result.data) ? result.data.length : 0;
    return { status: result.response.status, rows,
      denied: (result.response.status === 401 || result.response.status === 403) && rows === 0,
      code: typeof result.data?.code === 'string' && /^[A-Za-z0-9_]{1,12}$/u.test(result.data.code) ? result.data.code : null };
  };
  const describe = (item, result) => (result.unreached ? notReached(result)
    : `${item.denied ? '거부됨' : '거부되지 않음'} (HTTP ${item.status}${item.code ? `, 코드 ${item.code}` : ''}${item.rows ? `, 메모 ${item.rows}건이 응답됨` : ''})`);

  const read = await attempt(original, url, { headers: { apikey: key } });
  const insert = await attempt(original, url, { method: 'POST', headers: { apikey: key, ...json, prefer: 'return=minimal' }, body: '{}' });
  const target = `${url}?id=eq.${randomUUID()}`;
  const patch = await attempt(original, target, { method: 'PATCH', headers: { apikey: key, ...json, prefer: 'return=minimal' },
    body: JSON.stringify({ title: 'attack-check' }) });
  const remove = await attempt(original, target, { method: 'DELETE', headers: { apikey: key, prefer: 'return=minimal' } });
  const results = [
    ['original_api_anon_read', read],
    ['original_api_anon_insert', insert],
  ].map(([attackId, result]) => ({ attackId, expected: ORIGINAL_CHECKS.find(([id]) => id === attackId)[1],
    observed: describe(verdict(result) ?? {}, result) }));
  const modify = [patch, remove];
  const unreached = modify.find((result) => result.unreached);
  const parts = modify.map((result) => verdict(result));
  results.push({ attackId: 'original_api_anon_modify', expected: ORIGINAL_CHECKS[2][1],
    observed: unreached ? notReached(unreached)
      : `${parts.every((part) => part.denied) ? '거부됨' : '거부되지 않음'} (PATCH HTTP ${parts[0].status}${parts[0].code ? `, 코드 ${parts[0].code}` : ''}; DELETE HTTP ${parts[1].status}${parts[1].code ? `, 코드 ${parts[1].code}` : ''})` });

  const token = process.env.ATTACK_CHECK_TOKEN;
  if (!token) {
    results.push({ attackId: 'original_api_user_read', expected: ORIGINAL_CHECKS[3][1],
      observed: '미실행: 로그인 사용자 요청은 실제 토큰이 필요해 보내지 않았습니다 (환경변수 ATTACK_CHECK_TOKEN 없음).' });
  } else {
    const user = await attempt(original, url, { headers: { apikey: key, authorization: `Bearer ${token}` } });
    results.push({ attackId: 'original_api_user_read', expected: ORIGINAL_CHECKS[3][1], observed: describe(verdict(user) ?? {}, user) });
  }
  return results;
}

export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  const app = publicApp(config);
  if (config.step === 3) return runStepThree(config, app);
  if (config.step === 4) return [...await runStepThree(config, app), ...await runOwnerChecks(app)];
  if (config.step === 5) return [...await runStepThree(config, app), ...await runOwnerChecks(app), ...await runOriginalApiChecks(config)];
  const staticResponse = await request(app, '/data.json');
  const { data: staticData } = await readBody(staticResponse);
  const staticVisible = staticData?.sampleMarker === config.sampleMarker
    || (Array.isArray(staticData?.notes) && staticData.notes.length > 0);
  if (config.step === 1) {
    const visible = staticData?.sampleMarker === config.sampleMarker && Array.isArray(staticData.notes)
      && staticData.notes.length > 0;
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${staticResponse.status})` }];
  }
  const api = await request(app, '/api/notes');
  const { text, data } = await readBody(api);
  const count = Array.isArray(data?.notes) ? data.notes.length : 0;
  const headerText = [...api.headers].map(([name, value]) => `${name}: ${value}`).join('\n');
  const leaked = KEY_SHAPE.test(text) || KEY_SHAPE.test(headerText);
  return [
    { attackId: 'static_data_json_read', expected: '공개 /data.json에 가상 메모가 보이지 않음',
      observed: staticVisible ? '비로그인 요청에서 /data.json에 가상 메모가 보임'
        : `비로그인 요청에서 /data.json에 가상 메모가 보이지 않음 (HTTP ${staticResponse.status})` },
    { attackId: 'anonymous_api_read', expected: '키 없이 /api/notes를 부르면 가상 메모가 응답됨 (3단계 전까지 알려진 약점)',
      observed: api.ok && count > 0 ? `키 없이 요청해도 HTTP ${api.status}로 메모 ${count}건이 응답됨 (본문은 기록하지 않음)`
        : `키 없이 요청했을 때 메모가 응답되지 않음 (HTTP ${api.status})` },
    { attackId: 'api_key_not_exposed', expected: '/api/notes 응답 본문과 헤더에 서버 전용 키로 보이는 값이 없음',
      observed: leaked ? '응답 본문 또는 헤더에 키로 보이는 값이 있음' : '응답 본문과 헤더에 키로 보이는 값이 없음' },
  ];
}

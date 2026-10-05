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

export async function runAttackChecks(config) {
  if (![1, 2, 3].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  const app = publicApp(config);
  if (config.step === 3) return runStepThree(config, app);
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

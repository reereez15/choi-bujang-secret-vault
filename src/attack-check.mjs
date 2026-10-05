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

const request = (app, path) => fetch(new URL(path, app), {
  redirect: 'error', signal: AbortSignal.timeout(10000),
});

async function readBody(response) {
  const text = await response.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* 비JSON 응답은 점검 실패로 본다. */ }
  return { text, data };
}

export async function runAttackChecks(config) {
  if (![1, 2].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  const app = publicApp(config);
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

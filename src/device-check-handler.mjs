// 11단계: 기기 승인 확인 전용 경로. 로그인과 서버 판정기(decide)를 거친 결과만 승인으로 돌려준다.
// GET /api/device/check  →  200 { approved: true }  (로그인됨 + 판정기가 이 요청을 allow)
//                          403 { approved: false, reason } (판정기가 막음)  /  401 (로그인 안 됨)
// 보호 자료(메모 등)는 응답에 담지 않는다. 승인은 화면이 아니라 서버 판정기가 결정한다.
import { createLoginVerifier } from './verify-login.mjs';
import { decide } from './decider.mjs';
import { randomUUID } from 'node:crypto';

export function createDeviceCheckApi({
  env = process.env,
  createVerifier = createLoginVerifier,
  decideFn = decide,
  loadConfig = () => { throw new TypeError('missing_config_loader'); },
  log = console.error,
} = {}) {
  let verifier;
  const getVerifier = () => (verifier ??= createVerifier({ config: loadConfig(), supabaseSecretKey: env.SUPABASE_SECRET_KEY }));

  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Vary', 'Authorization');
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return res.status(405).json({ error: 'method_not_allowed' });
    }
    try {
      // 1) 서버가 로그인 토큰을 검증한다. 화면이 보낸 승인·역할 값은 신뢰하지 않는다.
      let identity;
      try { identity = await getVerifier().verify(req.headers?.authorization); }
      catch { identity = null; }
      if (!identity || typeof identity.userId !== 'string' || !identity.userId) {
        return res.status(401).json({ error: 'unauthorized', approved: false });
      }

      // 2) 승인 여부는 서버 판정기(decide)가 정한다. 화면이나 버튼이 아니다.
      //    계약 모양의 요청으로 메모 접근(GET /api/my/notes)을 판정기에 물어본다.
      //    deviceRegistered는 운영 릴레이가 보증하는 값이다. 미등록 기기는 릴레이가 판정기보다
      //    먼저 막으므로, 여기까지 온 요청은 등록 기기로 보고 판정기의 구역·규칙 검사를 거친다.
      const probe = {
        schema: 'aleph.decision.v1',
        requestId: randomUUID(),
        deviceRegistered: true,
        service: 'notes',
        method: 'GET',
        path: '/api/my/notes',
        route: 'GET /api/my/notes',
        stepUp: { verified: false, authAgeSeconds: null },
        recentEvents: [],
        signals: { source: 'none', region: 'unknown', network: 'unknown', hour: new Date().getUTCHours() },
      };
      const decision = await decideFn(probe);

      // 판정기가 허용(allow)할 때만 승인으로 본다. 그 밖(deny/step_up)은 자료실을 열지 않는다.
      if (!decision || decision.decision !== 'allow') {
        return res.status(403).json({ approved: false, reason: decision?.reasonCode ?? 'not_allowed' });
      }
      return res.status(200).json({ approved: true });
    } catch (error) {
      if (error instanceof TypeError && error.message === 'server_not_configured') {
        return res.status(500).json({ error: 'server_not_configured', approved: false });
      }
      log('device-check: 확인 중 예외가 발생했습니다.');
      return res.status(500).json({ error: 'server_error', approved: false });
    }
  };
}

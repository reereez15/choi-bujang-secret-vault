// 11단계: 기기 승인 확인 전용 경로. 로그인과 권한만 확인하고 보호 자료는 돌려주지 않는다.
// GET /api/device/check  →  200 { approved: true }  (로그인·권한 확인됨)  /  401·403 (아니면)
// 메모 본문 등 보호 자료를 절대 응답에 담지 않는다.
import { createLoginVerifier } from './verify-login.mjs';

export function createDeviceCheckApi({
  env = process.env,
  createVerifier = createLoginVerifier,
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
      // 서버가 로그인 토큰을 검증한다. 화면이 보낸 승인·역할 값은 신뢰하지 않는다.
      let identity;
      try { identity = await getVerifier().verify(req.headers?.authorization); }
      catch { identity = null; }
      if (!identity || typeof identity.userId !== 'string' || !identity.userId) {
        return res.status(401).json({ error: 'unauthorized' });
      }
      // 승인됨만 알린다. 자료는 담지 않는다.
      return res.status(200).json({ approved: true });
    } catch (error) {
      if (error instanceof TypeError && error.message === 'server_not_configured') {
        return res.status(500).json({ error: 'server_not_configured' });
      }
      log('device-check: 확인 중 예외가 발생했습니다.');
      return res.status(500).json({ error: 'server_error' });
    }
  };
}

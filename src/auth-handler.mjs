import { createClient as createSupabaseClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';

// 로그인·토큰 갱신·로그아웃을 서버가 Supabase Auth에 대신 부른다. 브라우저에는 Supabase 키도 SDK도 없다.
// 공개용 키(SUPABASE_PUBLISHABLE_KEY)와 서버 전용 키(SUPABASE_SECRET_KEY)는 서버 환경변수에서만 읽는다.
// 이메일·비밀번호·토큰은 저장하지 않고 응답이나 로그에 되돌려 쓰지 않는다. 로그에는 고정 문구와 짧은 오류 코드만 남긴다.
const EMAIL_MAX = 254;
const PASSWORD_MAX = 256;
const TOKEN_MAX = 4096;
const SAFE_CODE = /^[a-z0-9_]{1,40}$/u;
const BEARER = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/u;

// 브라우저가 받을 수 있는 오류 코드만 돌려준다. 그 밖의 Supabase 오류 문구는 밖으로 내보내지 않는다.
const LOGIN_ERRORS = {
  invalid_credentials: 401,
  email_not_confirmed: 403,
  user_banned: 403,
  email_provider_disabled: 403,
  over_request_rate_limit: 429,
  validation_failed: 400,
};
const REFRESH_ERRORS = new Set(['refresh_token_not_found', 'refresh_token_already_used', 'session_expired', 'session_not_found', 'bad_jwt']);

function parseBody(req) {
  let value = req.body;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

// 세션에서 브라우저가 필요한 값만 꺼낸다.
function publicSession(session) {
  if (!session || typeof session.access_token !== 'string' || typeof session.refresh_token !== 'string'
      || !Number.isFinite(session.expires_at) || typeof session.user?.id !== 'string') return null;
  return { access_token: session.access_token, refresh_token: session.refresh_token, expires_at: session.expires_at,
    user: { id: session.user.id, email: typeof session.user.email === 'string' ? session.user.email : null } };
}

export function createAuthApi({
  env = process.env,
  createClient = createSupabaseClient,
  log = console.error,
  loadConfig = () => { throw new TypeError('missing_config_loader'); },
  createVerifier = createLoginVerifier,
} = {}) {
  const options = { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } };
  const client = (key) => {
    if (!env.SUPABASE_URL || !key) throw new TypeError('server_not_configured');
    return createClient(env.SUPABASE_URL, key, options);
  };
  let verifier;
  const getVerifier = () => {
    verifier ??= createVerifier({ config: loadConfig(), supabaseSecretKey: env.SUPABASE_SECRET_KEY });
    return verifier;
  };

  const post = (run) => async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return res.status(405).json({ error: 'method_not_allowed' });
    }
    try {
      return await run(req, res);
    } catch (error) {
      if (error instanceof TypeError && error.message === 'server_not_configured') {
        log('auth: 서버 환경변수가 설정되지 않았습니다.');
        return res.status(500).json({ error: 'server_not_configured' });
      }
      log('auth: 요청 처리 중 예외가 발생했습니다.');
      return res.status(500).json({ error: 'server_error' });
    }
  };

  // Supabase가 돌려준 오류를 브라우저가 이해하는 코드로 바꾼다. 서버에 닿지 못한 경우는 502.
  const loginFailure = (error) => {
    const code = SAFE_CODE.test(String(error?.code ?? '')) ? error.code : null;
    if (error?.name === 'AuthRetryableFetchError' || error?.status === 0) return [502, 'upstream_unreachable', code];
    if (code && code in LOGIN_ERRORS) return [LOGIN_ERRORS[code], code, code];
    return [401, 'login_failed', code];
  };

  const login = post(async (req, res) => {
    const input = parseBody(req);
    if (!input || typeof input.email !== 'string' || !input.email.trim() || input.email.length > EMAIL_MAX
        || typeof input.password !== 'string' || !input.password || input.password.length > PASSWORD_MAX) {
      return res.status(400).json({ error: 'validation_failed' });
    }
    const { data, error } = await client(env.SUPABASE_PUBLISHABLE_KEY).auth
      .signInWithPassword({ email: input.email.trim(), password: input.password });
    const session = error ? null : publicSession(data?.session);
    if (!session) {
      const [status, code, logged] = loginFailure(error);
      log(`auth: 로그인에 실패했습니다 (${logged ?? code}).`);
      return res.status(status).json({ error: code });
    }
    return res.status(200).json(session);
  });

  const refresh = post(async (req, res) => {
    const input = parseBody(req);
    if (!input || typeof input.refresh_token !== 'string' || input.refresh_token.length < 8 || input.refresh_token.length > TOKEN_MAX) {
      return res.status(400).json({ error: 'validation_failed' });
    }
    const { data, error } = await client(env.SUPABASE_PUBLISHABLE_KEY).auth.refreshSession({ refresh_token: input.refresh_token });
    const session = error ? null : publicSession(data?.session);
    if (!session) {
      if (error?.name === 'AuthRetryableFetchError' || error?.status === 0) {
        log('auth: 토큰 갱신 중 Supabase에 닿지 못했습니다.');
        return res.status(502).json({ error: 'upstream_unreachable' });
      }
      const code = SAFE_CODE.test(String(error?.code ?? '')) ? error.code : 'unknown';
      log(`auth: 토큰 갱신에 실패했습니다 (${REFRESH_ERRORS.has(code) ? code : 'other'}).`);
      return res.status(401).json({ error: 'invalid_refresh_token' });
    }
    return res.status(200).json(session);
  });

  // 로그아웃은 로그인 토큰이 유효할 때만 이 세션을 서버에서도 끝낸다. 브라우저는 응답과 상관없이 자기 쪽 세션을 먼저 지운다.
  const logout = post(async (req, res) => {
    let verify;
    try {
      verify = getVerifier();
    } catch {
      log('auth: 로그인 검사 설정이 없어 로그아웃을 처리하지 않습니다.');
      return res.status(500).json({ error: 'login_not_configured' });
    }
    let identity = null;
    try { identity = await verify(req.headers?.authorization); } catch { identity = null; }
    const token = BEARER.exec(req.headers?.authorization ?? '')?.[1];
    if (!identity || !token) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return res.status(401).json({ error: 'unauthorized' });
    }
    const { error } = await client(env.SUPABASE_SECRET_KEY).auth.admin.signOut(token, 'local');
    if (error) {
      log('auth: 서버 쪽 로그아웃에 실패했습니다.');
      return res.status(502).json({ error: 'logout_failed' });
    }
    return res.status(200).json({ ok: true });
  });

  return { login, refresh, logout };
}

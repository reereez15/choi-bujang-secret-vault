// Supabase Auth 이메일·비밀번호 로그인 화면의 판단 로직.
// 비밀번호와 토큰은 공식 SDK(supabase-js)만 다룬다. 여기서 만들거나 저장하거나 출력하지 않는다.

const SAFE_CODE = /^[a-z0-9_]{1,60}$/u;

function jwtRole(key) {
  const parts = key.split('.');
  if (parts.length !== 3) return null;
  try {
    const base64 = parts[1].replace(/-/gu, '+').replace(/_/gu, '/');
    return JSON.parse(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='))).role ?? null;
  } catch {
    return null;
  }
}

// 설정이 화면에 쓸 수 있는 공개용 값인지 확인한다. 서버 전용 키로 보이면 SDK를 만들지 않는다.
export function checkAuthConfig(config) {
  const url = config?.url;
  const key = config?.publishableKey;
  if (typeof url !== 'string' || !url.trim() || typeof key !== 'string' || !key.trim()) {
    return { ok: false, reason: 'public/auth-config.js에 Project URL과 공개용(publishable) 키를 넣어 주세요.' };
  }
  let parsed;
  try { parsed = new URL(url); } catch {
    return { ok: false, reason: 'Project URL 형식이 맞지 않습니다. https://프로젝트ID.supabase.co 형태여야 합니다.' };
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.pathname !== '/'
      || parsed.search || parsed.hash || url !== url.trim()) {
    return { ok: false, reason: 'Project URL 형식이 맞지 않습니다. https://프로젝트ID.supabase.co 형태여야 합니다.' };
  }
  if (key !== key.trim() || /\s/u.test(key)) {
    return { ok: false, reason: '공개용 키에 공백이나 줄바꿈이 들어 있습니다.' };
  }
  if (key.startsWith('sb_secret_') || jwtRole(key) === 'service_role') {
    return { ok: false, reason: '서버 전용 키로 보입니다. 화면 코드에는 공개용(publishable) 키만 넣어야 합니다.' };
  }
  return { ok: true, url: parsed.origin, key };
}

// 로그인 실패를 화면에 보여 줄 한국어 이유로 바꾼다. 비밀번호나 토큰은 다루지 않는다.
export function describeAuthError(error) {
  const code = typeof error?.code === 'string' && SAFE_CODE.test(error.code) ? error.code : null;
  const status = Number.isInteger(error?.status) ? error.status : null;
  const name = typeof error?.name === 'string' ? error.name : '';
  let reason;
  if (code === 'invalid_credentials') reason = '이메일 또는 비밀번호가 맞지 않습니다.';
  else if (code === 'email_not_confirmed') reason = '이메일 인증이 끝나지 않은 계정입니다.';
  else if (code === 'user_banned') reason = '이 계정은 로그인이 막혀 있습니다.';
  else if (code === 'email_provider_disabled') reason = 'Supabase에서 이메일 로그인이 꺼져 있습니다.';
  else if (code === 'over_request_rate_limit' || status === 429) reason = '요청이 너무 많습니다. 잠시 뒤 다시 시도하세요.';
  else if (code === 'validation_failed') reason = '이메일 형식이나 입력값이 맞지 않습니다.';
  else if (name === 'AuthRetryableFetchError' || status === 0) reason = '서버에 연결하지 못했습니다. 네트워크를 확인하세요.';
  else if (status === 401 || (code && code.includes('api_key'))) reason = '공개용 키가 맞지 않습니다. public/auth-config.js의 키를 확인하세요.';
  else reason = '로그인하지 못했습니다.';
  const detail = code ? ` (코드: ${code})` : status ? ` (HTTP ${status})` : '';
  return `${reason}${detail}`;
}

// 로그인 화면 판 하나를 연결한다. 화면 상태는 body의 data-auth("in" 또는 "out")로도 남긴다.
export function mountAuthPanel({ root, config, sdk, onSession }) {
  const els = {
    badge: root.querySelector('[data-auth-badge]'),
    message: root.querySelector('[data-auth-message]'),
    form: root.querySelector('[data-auth-form]'),
    email: root.querySelector('[data-auth-email]'),
    password: root.querySelector('[data-auth-password]'),
    submit: root.querySelector('[data-auth-submit]'),
    signedIn: root.querySelector('[data-auth-signed-in]'),
    who: root.querySelector('[data-auth-who]'),
    logout: root.querySelector('[data-auth-logout]'),
  };
  const body = root.ownerDocument.body;
  const setMessage = (text, kind = 'info') => {
    els.message.textContent = text;
    els.message.dataset.kind = kind;
  };
  // 로그인 토큰이 바뀔 때만 알린다. 토큰은 SDK가 준 값을 그대로 넘기고 여기서 읽거나 만들지 않는다.
  let lastToken;
  const render = (session) => {
    const signedIn = Boolean(session?.user);
    const token = session?.access_token ?? null;
    if (token !== lastToken) {
      lastToken = token;
      onSession?.(session ?? null);
    }
    body.dataset.auth = signedIn ? 'in' : 'out';
    els.form.hidden = signedIn;
    els.signedIn.hidden = !signedIn;
    els.badge.textContent = signedIn ? '로그인 상태' : '로그아웃 상태';
    els.badge.dataset.state = signedIn ? 'in' : 'out';
    els.who.textContent = signedIn ? (session.user.email ?? '이메일 없음') : '';
  };

  const checked = checkAuthConfig(config);
  if (!checked.ok) {
    render(null);
    els.form.hidden = true;
    setMessage(checked.reason, 'error');
    return { ok: false, reason: checked.reason };
  }
  if (typeof sdk?.createClient !== 'function') {
    render(null);
    els.form.hidden = true;
    setMessage('로그인 SDK를 불러오지 못했습니다. 페이지를 새로고침하거나 배포 파일(vendor)을 확인하세요.', 'error');
    return { ok: false, reason: 'sdk_missing' };
  }

  const client = sdk.createClient(checked.url, checked.key, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: false },
  });
  render(null);
  setMessage('로그인하지 않았습니다.');
  // 로그인·로그아웃 이벤트가 이미 화면을 바꿨다면, 늦게 도착한 처음 세션 조회가 덮어쓰지 않게 한다.
  let sawEvent = false;
  // 새로고침했을 때 저장된 로그인이 복원되면 안내 문구도 로그인 상태에 맞게 바꾼다.
  const restored = () => setMessage('로그인한 상태입니다.', 'ok');
  client.auth.onAuthStateChange((event, session) => {
    sawEvent = true;
    render(session);
    if (event === 'INITIAL_SESSION' && session?.user) restored();
  });
  client.auth.getSession().then(({ data }) => {
    if (sawEvent) return;
    render(data?.session ?? null);
    if (data?.session?.user) restored();
  }).catch(() => setMessage('로그인 상태를 확인하지 못했습니다.', 'error'));

  els.form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = els.email.value.trim();
    const password = els.password.value;
    if (!email || !password) {
      setMessage('이메일과 비밀번호를 모두 입력하세요.', 'error');
      return;
    }
    els.submit.disabled = true;
    setMessage('로그인하는 중입니다.');
    try {
      const { error } = await client.auth.signInWithPassword({ email, password });
      if (error) setMessage(describeAuthError(error), 'error');
      else setMessage('로그인했습니다.', 'ok');
    } catch (error) {
      setMessage(describeAuthError(error), 'error');
    } finally {
      els.password.value = '';
      els.submit.disabled = false;
    }
  });

  els.logout.addEventListener('click', async () => {
    els.logout.disabled = true;
    try {
      const { error } = await client.auth.signOut();
      if (error) setMessage('로그아웃하지 못했습니다. 다시 시도하세요.', 'error');
      else setMessage('로그아웃했습니다.', 'ok');
    } catch {
      setMessage('로그아웃하지 못했습니다. 다시 시도하세요.', 'error');
    } finally {
      els.logout.disabled = false;
    }
  });
  return { ok: true };
}

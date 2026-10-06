// 로그인 화면의 판단 로직. 이 브라우저 코드에는 Supabase 키도 SDK도 없다.
// 로그인·토큰 갱신·로그아웃은 같은 서버의 /api/auth/* 함수가 Supabase Auth에 대신 부른다.
// 비밀번호는 서버로 보내기만 하고 저장하지 않는다. 서버가 돌려준 세션은 이 탭의 sessionStorage에만 둔다(탭을 닫으면 사라진다).

const STORAGE_KEY = 'vault.session';
const SAFE_CODE = /^[a-z0-9_]{1,40}$/u;
const MAX_TIMER = 2 ** 31 - 1;

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
  else if (code === 'server_not_configured') reason = '로그인 서버 설정이 아직 없습니다. 배포 환경변수를 확인하세요.';
  else if (name === 'AuthRetryableFetchError' || code === 'upstream_unreachable' || status === 0 || status === 502) reason = '서버에 연결하지 못했습니다. 네트워크를 확인하세요.';
  else reason = '로그인하지 못했습니다.';
  const detail = code ? ` (코드: ${code})` : status ? ` (HTTP ${status})` : '';
  return `${reason}${detail}`;
}

function validSession(value) {
  return value && typeof value === 'object' && typeof value.access_token === 'string' && value.access_token
    && typeof value.refresh_token === 'string' && value.refresh_token && Number.isFinite(value.expires_at)
    && typeof value.user?.id === 'string';
}

// 로그인 화면 판 하나를 연결한다. 화면 상태는 body의 data-auth("in" 또는 "out")로도 남긴다.
export function mountAuthPanel({
  root, onSession,
  fetchImpl = (...args) => globalThis.fetch(...args),
  storage = globalThis.sessionStorage,
  now = () => Date.now(),
  setTimer = (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimer = (id) => globalThis.clearTimeout(id),
}) {
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

  // 로그인 토큰이 바뀔 때만 화면 쪽에 알린다. 화면 쪽에는 리프레시 토큰을 넘기지 않는다.
  let lastToken;
  const render = (view) => {
    const signedIn = Boolean(view?.user);
    const token = view?.access_token ?? null;
    if (token !== lastToken) {
      lastToken = token;
      onSession?.(view ?? null);
    }
    body.dataset.auth = signedIn ? 'in' : 'out';
    els.form.hidden = signedIn;
    els.signedIn.hidden = !signedIn;
    els.badge.textContent = signedIn ? '로그인 상태' : '로그아웃 상태';
    els.badge.dataset.state = signedIn ? 'in' : 'out';
    els.who.textContent = signedIn ? (view.user.email ?? '이메일 없음') : '';
  };

  let session = null;
  let timer = null;
  let epoch = 0; // 로그인·로그아웃이 일어날 때마다 올려서, 늦게 도착한 갱신 응답이 세션을 되살리지 못하게 한다.

  const save = () => {
    try {
      if (session) storage.setItem(STORAGE_KEY, JSON.stringify(session));
      else storage.removeItem(STORAGE_KEY);
    } catch { /* 저장소를 못 쓰면 이 탭에서만 로그인이 유지된다. */ }
  };
  const view = () => (session ? { access_token: session.access_token, user: session.user } : null);

  async function call(path, { payload, token } = {}) {
    let response;
    try {
      response = await fetchImpl(path, {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify(payload ?? {}),
      });
    } catch {
      throw Object.assign(new Error('network'), { name: 'AuthRetryableFetchError', status: 0 });
    }
    let data = null;
    try { data = await response.json(); } catch { /* 본문이 없거나 JSON이 아니면 상태 코드만 쓴다. */ }
    if (!response.ok) throw Object.assign(new Error('api_error'), { status: response.status, code: typeof data?.error === 'string' ? data.error : null });
    return data;
  }

  function schedule() {
    if (timer !== null) clearTimer(timer);
    timer = null;
    if (!session) return;
    const wait = session.expires_at * 1000 - now() - 60000;
    timer = setTimer(refreshNow, Math.min(Math.max(wait, 5000), MAX_TIMER));
  }

  function setSession(next) {
    session = next;
    save();
    render(view());
    schedule();
  }

  async function refreshNow() {
    if (!session) return;
    const mine = epoch;
    try {
      const next = await call('/api/auth/refresh', { payload: { refresh_token: session.refresh_token } });
      if (mine !== epoch) return;
      if (!validSession(next)) throw Object.assign(new Error('bad_shape'), { status: 400 });
      setSession(next);
    } catch (error) {
      if (mine !== epoch) return;
      if (error.status === 400 || error.status === 401) {
        epoch += 1;
        setSession(null);
        setMessage('로그인이 만료됐습니다. 다시 로그인하세요.', 'error');
      } else {
        timer = setTimer(refreshNow, 30000); // 서버에 닿지 못했으면 잠시 뒤 다시 시도한다.
      }
    }
  }

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
      const next = await call('/api/auth/login', { payload: { email, password } });
      if (!validSession(next)) throw Object.assign(new Error('bad_shape'), { status: 502 });
      epoch += 1;
      setSession(next);
      setMessage('로그인했습니다.', 'ok');
    } catch (error) {
      setMessage(describeAuthError(error), 'error');
    } finally {
      els.password.value = '';
      els.submit.disabled = false;
    }
  });

  els.logout.addEventListener('click', async () => {
    const token = session?.access_token;
    els.logout.disabled = true;
    epoch += 1;
    setSession(null);
    setMessage('로그아웃했습니다.', 'ok');
    if (token) {
      try {
        await call('/api/auth/logout', { token });
      } catch (error) {
        if (error.status !== 401) setMessage('이 브라우저에서는 로그아웃했지만 서버에서 세션을 끝내지 못했습니다.', 'error');
      }
    }
    els.logout.disabled = false;
  });

  // 처음 열 때: 이 탭에 저장된 세션이 있으면 복원하고, 만료가 가까우면 먼저 갱신한다.
  render(null);
  setMessage('로그인하지 않았습니다.');
  let stored = null;
  try { stored = JSON.parse(storage.getItem(STORAGE_KEY) ?? 'null'); } catch { stored = null; }
  let ready = Promise.resolve();
  if (validSession(stored)) {
    session = stored;
    if (session.expires_at * 1000 - now() < 30000) {
      ready = refreshNow().then(() => { if (session) setMessage('로그인한 상태입니다.', 'ok'); });
    } else {
      render(view());
      schedule();
      setMessage('로그인한 상태입니다.', 'ok');
    }
  } else if (stored) {
    try { storage.removeItem(STORAGE_KEY); } catch { /* 무시 */ }
  }
  return { ok: true, ready };
}

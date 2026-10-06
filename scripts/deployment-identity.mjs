const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPO = /^[A-Za-z0-9._-]{1,100}$/u;
const SHA = /^[a-f0-9]{40}$/iu;
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/iu;

export function deploymentIdentity(env, config) {
  const owner = env.VERCEL_GIT_REPO_OWNER;
  const repo = env.VERCEL_GIT_REPO_SLUG;
  const commit = env.VERCEL_GIT_COMMIT_SHA;
  const host = env.VERCEL_URL;
  if (env.VERCEL_GIT_PROVIDER !== 'github' || !OWNER.test(owner || '')
      || !REPO.test(repo || '') || repo === '.' || repo === '..'
      || repo.toLowerCase().endsWith('.git') || !SHA.test(commit || '')
      || !HOST.test(host || '') || ![1, 2, 3, 4, 5].includes(config?.step)
      || typeof config.judgeIssuer !== 'string'
      || !/^https:\/\/[a-z0-9-]+\.up\.railway\.app\/defense\/judge$/iu.test(config.judgeIssuer)
      || typeof config.sampleMarker !== 'string'
      || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)) {
    throw new Error('배포 식별 정보를 확인할 수 없습니다. Vercel 시스템 환경변수와 1단계 시작 틀을 확인하세요.');
  }
  const identity = {
    schema: 'aleph.defense.deployment.v1',
    step: config.step,
    repoUrl: `https://github.com/${owner.toLowerCase()}/${repo.toLowerCase()}`,
    commit: commit.toLowerCase(),
    publicAppUrl: `https://${host.toLowerCase()}`,
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  };
  // 5단계부터 심판은 배포된 /aleph.json에서 원본 자료 API 주소를 읽는다. 주소가 없거나 모양이 틀리면 빌드를 멈춘다.
  // 3단계부터 심판은 배포된 /aleph.json에서 허용 경로를 읽는다. 하나 이상 있어야 하고, 모양이 틀리면 빌드를 멈춘다.
  if (config.step >= 3) identity.allowedRoutes = allowedRoutes(config.allowedRoutes);
  if (config.step >= 5) identity.originalApiUrl = originalApiUrl(config.originalApiUrl);
  return identity;
}

// "메서드 경로" 모양(예: GET /api/notes/:id)의 문자열 목록만 받는다.
const ROUTE = /^(?:GET|POST|PUT|PATCH|DELETE) \/[A-Za-z0-9/_:.-]{0,120}$/u;
function allowedRoutes(value) {
  if (!Array.isArray(value) || !value.length || value.length > 50
      || value.some((route) => typeof route !== 'string' || !ROUTE.test(route))) {
    throw new Error('허용 경로(allowedRoutes)를 확인할 수 없습니다. aleph.config.json에 "GET /api/notes" 같은 경로를 하나 이상 적어 주세요.');
  }
  return [...value];
}

// https로 시작하고 쿼리·해시·인증 정보가 없는 원본 자료 API 주소만 받는다.
function originalApiUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    url = null;
  }
  if (typeof value !== 'string' || !url || url.protocol !== 'https:' || url.search || url.hash
      || url.username || url.password || url.href !== value) {
    throw new Error('원본 자료 API 주소(originalApiUrl)를 확인할 수 없습니다. aleph.config.json에 쿼리 없는 https 주소를 적어 주세요.');
  }
  return value;
}

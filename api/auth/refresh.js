import { createAuthApi } from '../../src/auth-handler.mjs';

// POST /api/auth/refresh: 서버가 Supabase Auth에 로그인 토큰 갱신을 대신 부른다.
export default createAuthApi().refresh;

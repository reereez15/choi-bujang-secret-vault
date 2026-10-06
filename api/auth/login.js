import { createAuthApi } from '../../src/auth-handler.mjs';

// POST /api/auth/login: 서버가 Supabase Auth에 이메일·비밀번호 로그인을 대신 부른다.
export default createAuthApi().login;

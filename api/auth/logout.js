import { readFileSync } from 'node:fs';
import { createAuthApi } from '../../src/auth-handler.mjs';

// 로그아웃은 토큰 검사에 aleph.config.json(발급자 정보, 비밀 키 없음)을 읽는다.
const loadConfig = () => JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));

// POST /api/auth/logout: 유효한 로그인 토큰이면 이 세션을 서버에서도 끝낸다.
export default createAuthApi({ loadConfig }).logout;

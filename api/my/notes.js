import { readFileSync } from 'node:fs';
import { createNotesApi } from '../../src/notes-handler.mjs';

// 검사에 쓰는 발급자 정보는 저장소의 aleph.config.json(비밀 키 없음)에서 읽는다.
const loadConfig = () => JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));

// GET /api/my/notes (내 목록), POST /api/my/notes (추가).
// 기존 메모 핸들러의 collection을 그대로 쓴다 → 같은 서버 소유자 필터(본인 것만)가 유지된다.
export default createNotesApi({ loadConfig }).collection;

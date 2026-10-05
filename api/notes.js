import { readFileSync } from 'node:fs';
import { createNotesApi } from '../src/notes-handler.mjs';

// 검사에 쓰는 발급자 정보는 저장소의 aleph.config.json(비밀 키 없음)에서 읽는다.
const loadConfig = () => JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));

// GET /api/notes (목록), POST /api/notes (추가)
export default createNotesApi({ loadConfig }).collection;

import { readFileSync } from 'node:fs';
import { createRestoreApi } from '../../src/restore-handler.mjs';

const loadConfig = () => JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
// 비공개 가상 메모 사본을 읽는다(서버 함수 번들에 포함된다).
const loadBackup = () => JSON.parse(readFileSync(new URL('../../memo-backup.json', import.meta.url), 'utf8'));

// POST /api/restore/note { id } : 사본에서 지정한 ID 한 건만 복원.
export default createRestoreApi({ loadConfig, loadBackup });

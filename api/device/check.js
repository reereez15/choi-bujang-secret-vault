import { readFileSync } from 'node:fs';
import { createDeviceCheckApi } from '../../src/device-check-handler.mjs';

const loadConfig = () => JSON.parse(readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
// GET /api/device/check : 로그인·권한만 확인(승인 여부). 보호 자료는 돌려주지 않는다.
export default createDeviceCheckApi({ loadConfig });

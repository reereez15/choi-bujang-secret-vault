import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (![1, 2, 3, 4].includes(config.step)) {
  throw new Error('이 단계의 빌드 흐름을 scripts/build-public.mjs에 맞춰 주세요.');
}
await mkdir(resolve(root, 'public'), { recursive: true });
if (config.step === 1) {
  const source = resolve(root, 'data.json');
  const data = JSON.parse(await readFile(source, 'utf8'));
  if (!Array.isArray(data.notes)) {
    throw new Error('실습용 공개 자료 형식을 확인하세요. 실제 학생 자료를 넣으면 안 됩니다.');
  }
  await copyFile(source, resolve(root, 'public', 'data.json'));
  console.log('실습용 공개 자료를 public/data.json에 복사했습니다.');
} else {
  console.log(`${config.step}단계: 공개 data.json을 복사하지 않습니다. 자료는 /api/notes 서버 함수가 로그인을 확인한 뒤 DB에서 읽고 씁니다.`);
}
// 로그인 화면이 쓰는 공식 SDK 브라우저 번들을 같은 주소 아래로 복사한다 (외부 CDN을 쓰지 않는다).
const sdkSource = resolve(root, 'node_modules', '@supabase', 'supabase-js', 'dist', 'umd', 'supabase.js');
try {
  await mkdir(resolve(root, 'public', 'vendor'), { recursive: true });
  await copyFile(sdkSource, resolve(root, 'public', 'vendor', 'supabase.js'));
  console.log('공식 로그인 SDK를 public/vendor/supabase.js에 복사했습니다.');
} catch {
  throw new Error('공식 로그인 SDK 파일을 찾지 못했습니다. npm ci를 먼저 실행하세요.');
}
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}

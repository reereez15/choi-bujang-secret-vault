// 10단계 제작 1·2: 안전 정책 백업과 현재 시험 정책을 비교(--diff)하거나 되돌린다(--apply).
// 안전 정책 = aleph.config.json의 allowedRoutes. 백업은 policy-backup.json.
// 다른 설정(주소·발급자·step 등)과 감사 이력은 건드리지 않는다. git reset --hard는 쓰지 않는다.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const ROOT = resolve(fileURLToPath(import.meta.url), '..', '..');
const CONFIG = resolve(ROOT, 'aleph.config.json');
const BACKUP = resolve(ROOT, 'policy-backup.json');

function fail(message) {
  process.stderr.write(`중단: ${message}\n`);
  process.exitCode = 1;
  return null;
}

// 백업 사본을 읽고 검증한다. 없거나 해시가 안 맞으면 중단한다.
function loadVerifiedBackup() {
  let backup;
  try {
    backup = JSON.parse(readFileSync(BACKUP, 'utf8'));
  } catch {
    return fail('안전 정책 사본(policy-backup.json)이 없거나 읽을 수 없습니다.');
  }
  if (!backup?.policy || !Array.isArray(backup.policy.allowedRoutes)) {
    return fail('사본에 allowedRoutes가 없습니다. 검증 실패로 봅니다.');
  }
  const expected = createHash('sha256').update(JSON.stringify(backup.policy)).digest('hex');
  if (backup.sha256 !== expected) {
    return fail('사본 해시가 내용과 맞지 않습니다. 검증 실패로 봅니다.');
  }
  return backup;
}

// 현재 정책과 백업 정책의 차이를 계산한다(allowedRoutes만).
function diffRoutes(current, backup) {
  const cur = new Set(current);
  const bak = new Set(backup);
  const toRemove = current.filter((r) => !bak.has(r)); // 현재에만 있는 것(되돌리면 사라짐)
  const toAdd = backup.filter((r) => !cur.has(r));      // 백업에만 있는 것(되돌리면 생김)
  return { toRemove, toAdd, changed: toRemove.length > 0 || toAdd.length > 0 };
}

function printDiff(config, backup) {
  const d = diffRoutes(config.allowedRoutes ?? [], backup.policy.allowedRoutes);
  process.stdout.write('복원할 버전(검증된 안전 정책):\n');
  process.stdout.write(`  검증 시각: ${backup.verifiedAt}\n`);
  process.stdout.write(`  경로 수: ${backup.policy.allowedRoutes.length}\n\n`);
  process.stdout.write('실행하면 바뀔 범위(allowedRoutes만):\n');
  if (!d.changed) {
    process.stdout.write('  변경 없음 — 현재 정책이 이미 안전 정책과 같습니다.\n');
  } else {
    for (const r of d.toRemove) process.stdout.write(`  - 제거: ${r}\n`);
    for (const r of d.toAdd) process.stdout.write(`  + 추가: ${r}\n`);
  }
  process.stdout.write('\n다른 설정(주소·발급자·step 등)과 감사 이력은 보존됩니다.\n');
  return d;
}

const mode = process.argv[2];
const backup = loadVerifiedBackup();
if (!backup) process.exit(1);

const config = JSON.parse(readFileSync(CONFIG, 'utf8'));

if (mode === '--diff' || mode === undefined) {
  printDiff(config, backup);
  process.stdout.write('\n되돌리려면: npm run policy:restore -- --apply\n');
} else if (mode === '--apply') {
  const d = printDiff(config, backup);
  if (!d.changed) {
    process.stdout.write('\n되돌릴 것이 없어 파일을 바꾸지 않았습니다.\n');
  } else {
    // allowedRoutes만 안전 정책으로 교체한다. 나머지 키는 그대로 둔다.
    config.allowedRoutes = [...backup.policy.allowedRoutes];
    writeFileSync(CONFIG, JSON.stringify(config, null, 2) + '\n');
    process.stdout.write('\n안전 정책으로 되돌렸습니다(allowedRoutes만 교체, 나머지 보존).\n');
  }
} else {
  fail(`알 수 없는 옵션: ${mode} (쓸 수 있는 값: --diff, --apply)`);
}

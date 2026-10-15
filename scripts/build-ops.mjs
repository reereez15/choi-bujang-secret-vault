// 12단계 제작 1·2: 제출 묶음(artifacts/submission.json)에서 탈환 작전실 요약을 만든다.
// 비밀값·토큰·메모 본문은 담지 않는다. 각 점검을 실측/미실행으로 구분한다.
// 아직 실행하지 않은 시험을 임의로 통과 처리하지 않는다(observed 그대로를 상태로 쓴다).
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const ROOT = resolve(fileURLToPath(import.meta.url), '..', '..');
const SUB = resolve(ROOT, 'artifacts', 'submission.json');
const OUT = resolve(ROOT, 'public', 'ops.json');

let sub;
try {
  sub = JSON.parse(readFileSync(SUB, 'utf8'));
} catch {
  console.error('작전실 요약을 만들 수 없습니다: artifacts/submission.json이 없습니다. 먼저 npm run bundle을 실행하세요.');
  process.exit(1);
}

// 점검 하나의 상태를 정한다. observed가 정확히 'not_run'이면 미실행, HTTP 상태가 적혀 있으면 실측.
function statusOf(observed) {
  const text = typeof observed === 'string' ? observed.trim() : '';
  if (text === 'not_run' || /^미실행|not run/i.test(text)) return 'not_run';
  return 'measured';
}

const attempts = Array.isArray(sub.attackAttempts) ? sub.attackAttempts : [];
const checks = attempts.map((a) => ({
  id: a.attackId,
  expected: a.expected,           // 기대 결과
  observed: a.observed,           // 실제 API 결과(또는 미실행 사유). 메모 본문은 묶음 단계에서 이미 제외됨.
  status: statusOf(a.observed),
}));

const measured = checks.filter((c) => c.status === 'measured').length;
const notRun = checks.filter((c) => c.status === 'not_run').length;

// 제공 엔진(ALEPH SDP)이 가상 요청으로 확인하는 항목은 배포 자기점검에 포함되지 않는다.
// 로컬에서 실행한 41종 전체 규칙 시험(test:r5)과 판정기/탐지 연습은 별도 명령이다.
const ops = {
  schema: 'aleph.ops.summary.v1',
  generatedFrom: 'artifacts/submission.json',
  step: sub.step,
  commit: sub.commit,
  repoUrl: sub.repoUrl,
  // 학생이 만든 규칙 요약
  policyRules: Array.isArray(sub.policyRules) ? sub.policyRules : [],
  allowedRoutes: Array.isArray(sub.allowedRoutes) ? sub.allowedRoutes : [],
  restoreRoute: sub.restoreRoute ?? null,
  detect: { rule: 'burst_read', window: '10분', threshold: '120건 초과', action: 'propose_revocation' },
  // 회수 상태·복구 버전
  revocation: { source: 'detect.mjs (가상 사건 연습)', note: '실제 회수 집행은 ALEPH SDP 엔진이 확인(미실행)' },
  restore: { policyBackup: 'policy-backup.json', memoBackup: 'memo-backup.json', route: sub.restoreRoute ?? null },
  // 배포 자기점검 결과 요약(실측/미실행)
  checks,
  totals: { total: checks.length, measured, notRun },
  // 출처 구분: 아래 점검은 학생 코드가 배포 서버에 보낸 실제 요청 결과다.
  // 판정기 기기 등록·복합 이상·구역 규칙과 미등록 기기 공격 등은 ALEPH SDP 엔진이 가상 요청으로 확인한다.
  engine: 'ALEPH SDP 엔진',
  generatedAt: new Date().toISOString(),
};

mkdirSync(resolve(ROOT, 'public'), { recursive: true });
writeFileSync(OUT, `${JSON.stringify(ops, null, 2)}\n`, 'utf8');
console.log(`작전실 요약을 public/ops.json에 기록했습니다 (실측 ${measured} · 미실행 ${notRun} · 전체 ${checks.length}).`);

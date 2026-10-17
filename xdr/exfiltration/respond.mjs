// xdr/exfiltration/respond.mjs
// decide.mjs 의 판단 결과를 받아 대응한다.
// - block 인 경보만 거부 규칙 후보(blocklist.json)로 적는다. 만료 시각과 근거 경보 번호를 붙인다.
// - 같은 주소가 record(정상) 경보에도 나오면 후보에 넣지 않는다(정상 사용자 보호).
// - block·alert 는 xdr/alerts.log 에 한 줄씩 쌓는다. 비밀값은 쓰지 않는다.
// - checkSource() 는 판정기에 꽂을 확인 단계 부품이다. 'deny' 또는 'no_opinion' 만 돌려주고 'allow' 는 만들지 않는다.
//
// 주의: 판정기 요청 계약(docs/DECIDER_REQUEST.md)에는 출발 주소가 없다.
// 그래서 이 파일은 src/decider.mjs 를 고치지 않고, 실제 판정기에 연결됐다고 주장하지 않는다.
//
// 사용: node xdr/exfiltration/respond.mjs [경보파일]

import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const DEFAULT_FIXTURE = here('../fixtures/exfiltration.json');
const BLOCKLIST_PATH = here('./blocklist.json');
const ALERTS_LOG_PATH = here('../alerts.log');

export const RULE_ID = 'xdr.exfiltration.deny';
export const BLOCK_TTL_MS = 60 * 60 * 1000; // 차단 후보는 근거 경보 시각부터 1시간 뒤 만료

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const isIp = (v) => typeof v === 'string' && (IPV4.test(v) || /^[0-9A-Fa-f:]+$/.test(v) && v.includes(':'));
const oneLine = (v) => String(v ?? '').replace(/[\r\n\t]+/g, ' ').slice(0, 200);

/** 경보 목록 → 판단 결과 목록 */
export function judgeAll(alerts) {
  return alerts.map((alert) => ({ alert, decision: decide(alert) }));
}

/** 판단 결과 → 거부 규칙 후보 (주소별로 묶음) */
export function buildBlocklist(judged) {
  const normalIps = new Set(
    judged
      .filter((j) => j.decision.action === 'record')
      .map((j) => j.alert?.data?.srcip)
      .filter(isIp)
  );

  const byIp = new Map();
  const skipped = [];
  for (const { alert, decision } of judged) {
    if (decision.action !== 'block') continue;
    const ip = alert?.data?.srcip;
    if (!isIp(ip)) {
      skipped.push({ alertId: alert?.id ?? null, why: '출발 주소 없음' });
      continue;
    }
    if (normalIps.has(ip)) {
      skipped.push({ alertId: alert.id, srcip: ip, why: '같은 주소에 정상 경보가 있음' });
      continue;
    }
    const seen = Date.parse(alert.timestamp);
    const expires = Number.isFinite(seen) ? seen + BLOCK_TTL_MS : null;
    const rule = byIp.get(ip) ?? {
      ruleId: RULE_ID,
      action: 'deny',
      srcip: ip,
      expiresAt: null,
      alertIds: [],
      reasons: [],
      maxConfidence: 0,
    };
    rule.alertIds.push(alert.id);
    rule.reasons.push(oneLine(decision.reason));
    rule.maxConfidence = Math.max(rule.maxConfidence, decision.confidence);
    if (expires !== null) {
      const cur = rule.expiresAt ? Date.parse(rule.expiresAt) : 0;
      if (expires > cur) rule.expiresAt = new Date(expires).toISOString();
    }
    byIp.set(ip, rule);
  }

  return {
    schema: 'aleph.xdr.blocklist.v1',
    moduleKey: 'exfiltration',
    note: '판정기 요청 계약에 출발 주소가 없어 src/decider.mjs 에는 연결하지 않은 거부 규칙 후보입니다.',
    rules: [...byIp.values()],
    skipped,
  };
}

/**
 * 판정기 확인 단계 부품. 출발 주소가 차단 후보에 있고 만료 전이면 deny, 아니면 no_opinion.
 * allow 는 절대 돌려주지 않으므로 판정기의 기존 규칙을 대신하지 않는다.
 */
export function checkSource(blocklist, srcip, now = Date.now()) {
  const rule = blocklist?.rules?.find((r) => r.srcip === srcip);
  if (!rule) return { result: 'no_opinion' };
  if (rule.expiresAt && Date.parse(rule.expiresAt) <= now) return { result: 'no_opinion' };
  return {
    result: 'deny',
    ruleId: rule.ruleId,
    reason: `자료 빼돌리기 차단 후보 (근거 경보 ${rule.alertIds.join(', ')})`,
    expiresAt: rule.expiresAt,
  };
}

/** alerts.log 에 쓸 줄들 (block·alert 만) */
export function logLines(judged, at = new Date().toISOString()) {
  return judged
    .filter((j) => j.decision.action === 'block' || j.decision.action === 'alert')
    .map(({ alert, decision }) =>
      [
        at,
        decision.action.toUpperCase(),
        'module=exfiltration',
        `alert=${oneLine(alert?.id)}`,
        `src=${isIp(alert?.data?.srcip) ? alert.data.srcip : '-'}`,
        `confidence=${decision.confidence}`,
        `reason=${oneLine(decision.reason)}`,
      ].join(' | ')
    );
}

// ── 명령줄 실행 ──────────────────────────────────────────────
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];

if (isMain) {
  const path = process.argv[2] ?? DEFAULT_FIXTURE;
  try {
    const fixture = JSON.parse(await readFile(path, 'utf8'));
    const alerts = Array.isArray(fixture) ? fixture : fixture.alerts ?? [];
    const judged = judgeAll(alerts);

    const blocklist = buildBlocklist(judged);
    await writeFile(BLOCKLIST_PATH, JSON.stringify(blocklist, null, 2) + '\n', 'utf8');

    const lines = logLines(judged);
    if (lines.length) await appendFile(ALERTS_LOG_PATH, lines.join('\n') + '\n', 'utf8');

    // 시험 경보를 다시 흘려 확인: 각 경보 시각 기준으로 출발 주소를 확인 단계에 넣는다.
    let blockedAttack = 0, blockedOther = 0, passedNormal = 0, normalTotal = 0;
    for (const { alert, decision } of judged) {
      const r = checkSource(blocklist, alert?.data?.srcip, Date.parse(alert.timestamp));
      if (decision.action === 'record') {
        normalTotal++;
        if (r.result === 'deny') blockedOther++;
        else passedNormal++;
      } else if (r.result === 'deny') {
        decision.action === 'block' ? blockedAttack++ : blockedOther++;
      }
    }
    const attackTotal = judged.filter((j) => j.decision.action === 'block').length;

    console.log(`차단 후보 주소 ${blocklist.rules.length}개 → ${BLOCKLIST_PATH}`);
    console.log(`알림 ${lines.length}줄 추가 → ${ALERTS_LOG_PATH}`);
    console.log(`다시 흘리기: 명확한 공격 ${blockedAttack}/${attackTotal} 차단, 정상 ${passedNormal}/${normalTotal} 통과, 그 밖에 막힌 경보 ${blockedOther}건`);
    const ok = blockedAttack === attackTotal && passedNormal === normalTotal && blockedOther === 0;
    console.log(`확인: ${ok ? '명확한 공격만 막히고 정상은 통과' : '기준 불일치'}`);
    process.exitCode = ok ? 0 : 1;
  } catch (err) {
    console.error(`대응 실패: ${err.message}`);
    process.exitCode = 2;
  }
}

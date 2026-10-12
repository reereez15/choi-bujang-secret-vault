// xdr/web-injection/read-alerts.mjs
// Wazuh 경보를 읽어 시각·출발 주소·계정·규칙 수준·설명만 뽑는 읽기 전용 모듈.
// 확인용 모듈이다. decide.mjs 는 이 파일을 불러오지 않는다.
// - 원본 파일은 읽기만 한다(쓰기 호출 없음).
// - 비밀값처럼 보이는 값은 [가림]으로 바꿔 출력한다.
// - 경보 한 건당 정확히 한 줄을 만든다(필드가 없으면 null).
//
// 사용: node xdr/web-injection/read-alerts.mjs [경보파일]
//       (기본값: xdr/fixtures/web-injection.json)

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const DEFAULT_FIXTURE = fileURLToPath(
  new URL("../fixtures/web-injection.json", import.meta.url)
);

const MASK = "[가림]";

// 비밀값처럼 보이는 패턴
const SECRET_PATTERNS = [
  // key=value / key: value 형태 (password, token, secret, api key 등)
  /\b(?<key>pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|session(?:id)?|cookie|authorization)\b(?<sep>\s*[:=]\s*|\s+)(?:"[^"]*"|'[^']*'|\S+)/gi,
  // Bearer / Basic 인증 값
  /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/g,
  // JWT
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g,
  // AWS 접근 키 ID
  /\bAKIA[0-9A-Z]{16}\b/g,
  // 긴 16진수·base64 덩어리 (해시, 키 등)
  /\b[A-Fa-f0-9]{32,}\b/g,
  /\b[A-Za-z0-9+/_-]{40,}={0,2}/g,
];

/** 문자열 안의 비밀값처럼 보이는 부분을 가린다. */
export function redact(value) {
  if (value === null || value === undefined) return null;
  let s = String(value);
  // key=value 형태는 키 이름은 남기고 값만 가린다
  s = s.replace(SECRET_PATTERNS[0], (...args) => {
    const { key, sep } = args.at(-1);
    return `${key}${sep}${MASK}`;
  });
  for (const re of SECRET_PATTERNS.slice(1)) s = s.replace(re, MASK);
  return s;
}

/** 계정 칸: 값 전체가 비밀처럼 보이면 통째로 가린다. */
function redactUser(value) {
  if (value === null || value === undefined || value === "") return null;
  const s = String(value);
  return redact(s) !== s ? MASK : s;
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9A-Fa-f:]+$/;

/** 주소 칸: IP 모양이 아니면 출력하지 않는다. */
function cleanIp(value) {
  if (value === null || value === undefined || value === "") return null;
  const s = String(value).trim();
  return IPV4.test(s) || (s.includes(":") && IPV6.test(s)) ? s : MASK;
}

const pick = (obj, paths) => {
  for (const p of paths) {
    const v = p.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return null;
};

/** 파일 텍스트 → 경보 객체 배열 (배열 / NDJSON / {alerts} / hits.hits 지원) */
export function parseAlerts(text) {
  const trimmed = text.trim();
  if (trimmed === "") return [];

  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    // NDJSON: 빈 줄을 제외한 한 줄 = 경보 한 건
    return trimmed
      .split(/\r?\n/)
      .filter((line) => line.trim() !== "")
      .map((line, i) => {
        try {
          return JSON.parse(line);
        } catch {
          throw new Error(`${i + 1}번째 줄을 JSON으로 읽을 수 없습니다.`);
        }
      });
  }

  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed?.alerts)) return parsed.alerts;
  if (Array.isArray(parsed?.hits?.hits))
    return parsed.hits.hits.map((h) => h?._source ?? h);
  if (parsed && typeof parsed === "object" && parsed.rule) return [parsed];
  throw new Error("경보 목록을 찾지 못했습니다(배열, NDJSON, alerts, hits.hits 중 아님).");
}

/** 경보 한 건 → 출력할 다섯 칸 */
export function extractRow(alert) {
  return {
    time: pick(alert, ["timestamp", "@timestamp"]),
    srcip: cleanIp(
      pick(alert, ["data.srcip", "data.src_ip", "data.win.eventdata.ipAddress"])
    ),
    user: redactUser(
      pick(alert, [
        "data.srcuser",
        "data.dstuser",
        "data.user",
        "data.win.eventdata.targetUserName",
      ])
    ),
    level: pick(alert, ["rule.level"]),
    description: redact(pick(alert, ["rule.description"])),
  };
}

/** 파일을 읽어 { alertCount, rows } 를 돌려준다. 파일은 읽기만 한다. */
export async function readAlerts(path = DEFAULT_FIXTURE) {
  const text = await readFile(path, "utf8");
  const alerts = parseAlerts(text);
  const rows = alerts.map(extractRow);
  return { alertCount: alerts.length, rows };
}

// ── 명령줄 실행 ──────────────────────────────────────────────
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];

if (isMain) {
  const path = process.argv[2] ?? DEFAULT_FIXTURE;
  try {
    const { alertCount, rows } = await readAlerts(path);
    for (const row of rows) console.log(JSON.stringify(row));
    const ok = alertCount === rows.length;
    console.error(
      `확인: 경보 ${alertCount}건 / 뽑은 줄 ${rows.length}줄 → ${ok ? "일치" : "불일치"}`
    );
    process.exitCode = ok ? 0 : 1;
  } catch (err) {
    console.error(`읽기 실패: ${err.message}`);
    process.exitCode = 2;
  }
}

// xdr/brute-force/decide.mjs
// 무차별 로그인 경보 판단기. 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부른다.
// 규칙: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않는다. 이 파일 안에서 혼자 계산한다.
// 판단 결과만 돌려준다. 알림 기록과 판정기 연결은 respond.mjs 에서 한다.

// xdr/brute-force/patterns.json 의 patterns 를 그대로 옮겨 적은 상수 (근거: MITRE ATT&CK T1110)
export const PATTERNS = [
  {
    "name": "같은 주소의 로그인 실패 연속",
    "technique": "T1110.001",
    "match": {
      "description": "한 출발 주소(data.srcip)에서 로그인 실패가 짧은 시간에 연속으로 쌓인다. 실패 횟수는 data.count(문자열이라 숫자로 바꿔 비교)로 본다.",
      "countField": "data.count",
      "strongAtLeast": 15,
      "weakAtLeast": 3
    },
    "evidence": "MITRE ATT&CK T1110.001 Password Guessing: 계정 하나에 비밀번호를 반복해 넣으면 같은 출발 주소에서 로그인 실패가 연속으로 쌓인다 (https://attack.mitre.org/techniques/T1110/001/)."
  },
  {
    "name": "여러 계정에 같은 비밀번호 대입",
    "technique": "T1110.003",
    "match": {
      "description": "한 출발 주소가 여러 계정에 같은 비밀번호로 로그인 실패를 낸다. 계정 수는 data.accounts(쉼표로 나뉜 목록)로 보고, 목록이 없으면 설명의 '같은 비밀번호'와 data.count를 함께 본다.",
      "accountsField": "data.accounts",
      "strongAccountsAtLeast": 5,
      "weakAccountsAtLeast": 2,
      "descriptionHint": "같은 비밀번호"
    },
    "evidence": "MITRE ATT&CK T1110.003 Password Spraying: 흔한 비밀번호 하나를 여러 계정에 돌려 넣으면 한 출발 주소에서 여러 계정의 로그인 실패가 나타난다 (https://attack.mitre.org/techniques/T1110/003/)."
  }
];

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

const [GUESSING, SPRAYING] = PATTERNS;

function toCount(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function countAccounts(value) {
  if (typeof value !== 'string' || value.trim() === '') return 0;
  return new Set(value.split(',').map((s) => s.trim()).filter(Boolean)).size;
}

// 약한 기준~뚜렷한 기준 사이를 0.5~0.8 로, 뚜렷한 기준 이상을 0.9~0.99 로 매긴다.
function scale(value, weak, strong) {
  if (value >= strong) return Math.min(0.99, 0.9 + (value - strong) / (strong * 20));
  if (value >= weak) return 0.5 + ((value - weak) / (strong - weak)) * 0.3;
  return 0;
}

// T1110.001: 같은 주소의 로그인 실패 연속
function matchGuessing(alert) {
  const m = GUESSING.match;
  const count = toCount(alert?.data?.count);
  return { score: scale(count, m.weakAtLeast, m.strongAtLeast), note: `실패 ${count}건` };
}

// T1110.003: 여러 계정에 같은 비밀번호 대입
function matchSpraying(alert) {
  const m = SPRAYING.match;
  const accounts = countAccounts(alert?.data?.accounts);
  if (accounts > 0) {
    return {
      score: scale(accounts, m.weakAccountsAtLeast, m.strongAccountsAtLeast),
      note: `계정 ${accounts}개`,
    };
  }
  // 계정 목록이 없으면 설명의 '같은 비밀번호'가 있을 때만 실패 횟수로 본다.
  const description = String(alert?.rule?.description ?? '');
  if (!description.includes(m.descriptionHint)) return { score: 0, note: '' };
  const g = GUESSING.match;
  const count = toCount(alert?.data?.count);
  return { score: scale(count, g.weakAtLeast, g.strongAtLeast), note: `실패 ${count}건` };
}

export function decide(alert) {
  const results = [
    { pattern: GUESSING, ...matchGuessing(alert) },
    { pattern: SPRAYING, ...matchSpraying(alert) },
  ].filter((r) => r.score > 0);

  if (results.length === 0) {
    return { action: 'record', confidence: 0, reason: '일치하는 무차별 로그인 패턴 없음' };
  }

  results.sort((a, b) => b.score - a.score);
  const confidence = Math.round(results[0].score * 100) / 100;
  const action = confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record';
  const reason = results
    .map((r) => `${r.pattern.name}(${r.pattern.technique}, ${r.note})`)
    .join(' + ');
  return { action, confidence, reason };
}

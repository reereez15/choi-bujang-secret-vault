// xdr/web-injection/decide.mjs
// 웹 주입 경보 판단기. 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부른다.
// 규칙: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않는다. 이 파일 안에서 혼자 계산한다.
// 판단 결과만 돌려준다. 알림 기록과 판정기 연결은 respond.mjs 에서 한다.

// xdr/web-injection/patterns.json 의 patterns 를 그대로 옮겨 적은 상수 (근거: MITRE ATT&CK T1190)
export const PATTERNS = [
  {
    "name": "요청 인자 안의 SQL 구문",
    "technique": "T1190",
    "weakness": "CWE-89",
    "match": {
      "description": "경보 설명에 SQL 구문·SQL 표식·데이터베이스 조회를 이어 붙인 표기가 있고, 같은 주소에서 반복된다. 반복 횟수는 data.count(문자열이라 숫자로 바꿔 비교)로 본다. 'SQL'이라는 단어 하나만으로는 맞추지 않는다.",
      "descriptionAny": [
        "SQL 구문",
        "SQL 표식",
        "데이터베이스 조회를 이어 붙"
      ],
      "countField": "data.count",
      "strongAtLeast": 5,
      "weakAtLeast": 1
    },
    "evidence": "MITRE ATT&CK T1190: 공개된 웹 앱의 요청 인자에 SQL 구문을 넣어 데이터베이스 질의를 바꾸는 것이 대표적 악용 방식이다(CWE-89 SQL Injection, https://cwe.mitre.org/data/definitions/89.html)."
  },
  {
    "name": "요청 인자 안의 스크립트 태그",
    "technique": "T1190",
    "weakness": "CWE-79",
    "match": {
      "description": "경보 설명에 스크립트 삽입 표기나 스크립트 표식이 있고, 같은 주소에서 반복된다. '스크립트'라는 수업 단어 하나만으로는 맞추지 않는다.",
      "descriptionAny": [
        "스크립트 삽입",
        "스크립트 표식"
      ],
      "countField": "data.count",
      "strongAtLeast": 5,
      "weakAtLeast": 1
    },
    "evidence": "MITRE ATT&CK T1190: 공개된 웹 앱의 입력에 스크립트 태그를 넣어 다른 사용자의 화면에서 실행되게 하는 것도 앱 악용에 쓰인다(CWE-79 Cross-site Scripting, https://cwe.mitre.org/data/definitions/79.html)."
  },
  {
    "name": "경로 거슬러 올라가기(../) 반복",
    "technique": "T1190",
    "weakness": "CWE-22",
    "match": {
      "description": "경보 설명에 경로를 거슬러 올라가는 표기나 경로 이탈 표기가 있고, 같은 주소에서 반복된다. 경로에 'up'이 한 번 있는 것만으로는 맞추지 않는다.",
      "descriptionAny": [
        "거슬러 올라가",
        "경로 이탈"
      ],
      "countField": "data.count",
      "strongAtLeast": 5,
      "weakAtLeast": 1
    },
    "evidence": "MITRE ATT&CK T1190: 공개된 웹 앱의 파일 경로 인자에 ../ 를 반복해 허용된 폴더 밖 파일을 읽는 것이 알려진 악용 방식이다(CWE-22 Path Traversal, https://cwe.mitre.org/data/definitions/22.html)."
  },
  {
    "name": "요청 인자 안의 명령 구분자",
    "technique": "T1190",
    "weakness": "CWE-78",
    "match": {
      "description": "경보 설명에 명령 구분자 표기가 있고, 연속 요청에서 반복된다. 이름 검색의 구분 문자 한 건만으로는 맞추지 않는다.",
      "descriptionAny": [
        "명령 구분자"
      ],
      "countField": "data.count",
      "strongAtLeast": 5,
      "weakAtLeast": 1
    },
    "evidence": "MITRE ATT&CK T1190: 공개된 웹 앱의 인자에 ; | & 같은 명령 구분자를 넣어 서버 명령을 이어 실행하게 하는 것이 알려진 악용 방식이다(CWE-78 OS Command Injection, https://cwe.mitre.org/data/definitions/78.html)."
  }
];

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const TECHNIQUE = 'T1190';
// 공격 표기는 없지만 Wazuh 규칙이 T1190 으로 표시한 단발 요청: 사람이 볼 수 있게 alert 까지만 올린다.
const TAGGED_ONLY_SCORE = 0.55;

function toCount(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

// 약한 기준~뚜렷한 기준 사이를 0.5~0.8 로, 뚜렷한 기준 이상을 0.9~0.99 로 매긴다.
function scale(value, weak, strong) {
  if (value >= strong) return Math.min(0.99, 0.9 + (value - strong) / (strong * 20));
  if (value >= weak) return 0.5 + ((value - weak) / Math.max(1, strong - weak)) * 0.3;
  return 0;
}

function matchPattern(pattern, description, count) {
  const m = pattern.match;
  const hit = m.descriptionAny.some((phrase) => description.includes(phrase));
  if (!hit) return 0;
  // 표기는 있는데 횟수가 비어 있으면 한 번으로 본다.
  return scale(Math.max(count, 1), m.weakAtLeast, m.strongAtLeast);
}

export function decide(alert) {
  const description = String(alert?.rule?.description ?? '');
  const count = toCount(alert?.data?.count);
  const tagged = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes(TECHNIQUE);

  const hits = PATTERNS.map((pattern) => ({ pattern, score: matchPattern(pattern, description, count) }))
    .filter((h) => h.score > 0)
    .sort((a, b) => b.score - a.score);

  if (hits.length > 0) {
    // 서로 다른 주입 표기가 함께 나오면 조금 더 뚜렷하다고 본다.
    const bonus = Math.min(0.05, (hits.length - 1) * 0.03);
    const confidence = Math.round(Math.min(0.99, hits[0].score + bonus) * 100) / 100;
    const action = confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record';
    const names = hits.map((h) => h.pattern.name + '(' + h.pattern.technique + ', ' + h.pattern.weakness + ')').join(' + ');
    return { action, confidence, reason: names + ', 반복 ' + count + '회' };
  }

  if (tagged) {
    return {
      action: 'alert',
      confidence: TAGGED_ONLY_SCORE,
      reason: '외부 공개 앱 악용 표시(' + TECHNIQUE + ')만 있고 주입 패턴 표기·반복 없음, 반복 ' + count + '회',
    };
  }

  return { action: 'record', confidence: 0, reason: '일치하는 웹 주입 패턴 없음' };
}

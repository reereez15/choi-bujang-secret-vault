// xdr/known-cve/decide.mjs
// 알려진 취약점 악용(CVE-2021-44228 / Log4Shell) 경보 판단기.
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부른다.
// 규칙: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않는다. 이 파일 안에서 혼자 계산한다.
// 판단 결과만 돌려준다. 알림 기록과 판정기 연결은 respond.mjs 에서 한다.

// xdr/known-cve/patterns.json 의 patterns 를 그대로 옮겨 적은 상수 (근거: CVE-2021-44228, MITRE ATT&CK T1190)
export const PATTERNS = [
  {
    "name": "요청 머리글·인자 안의 원격 조회 구문(jndi 형태)",
    "technique": "T1190",
    "weakness": "CVE-2021-44228",
    "match": {
      "description": "경보 설명에 CVE-2021-44228 형태 요청과 원격 조회 구문(머리글·주소 인자)이 함께 있다. 'jndi 라는 단어만', '중괄호만', '잘린 구문', '이름만 검색'은 맞추지 않는다.",
      "descriptionAll": ["CVE-2021-44228 형태 요청"],
      "descriptionAny": ["머리글에 원격 조회 구문", "주소 인자에 원격 조회 구문", "같은 CVE-2021-44228 표기", "그대로 있습니다", "머리글과 주소에 같이"],
      "descriptionNone": ["단어만", "글자만", "구문은 없", "중괄호가 한 번", "잘린", "이름만", "비슷한 수업용"]
    },
    "evidence": "CVE-2021-44228(Log4Shell): 요청 머리글·인자에 ${jndi:ldap://...} 형태의 원격 조회 구문을 넣어 취약한 Log4j가 외부 주소에서 코드를 끌어오게 만드는 것이 대표적 악용 방식이다."
  },
  {
    "name": "같은 주소의 원격 조회 구문 반복",
    "technique": "T1190",
    "weakness": "CVE-2021-44228",
    "match": {
      "description": "같은 출발 주소에서 원격 조회 구문이 여러 번 반복된다. 반복 횟수는 data.count(문자열이라 숫자로 바꿔 비교)로 본다. 한 번뿐이면 이 패턴으로 치지 않는다.",
      "descriptionAny": ["번 반복됐습니다", "번 들어왔습니다"],
      "countField": "data.count",
      "strongAtLeast": 5,
      "weakAtLeast": 2
    },
    "evidence": "MITRE ATT&CK T1190: 공개된 웹 앱에 같은 악용 요청을 자동화 도구로 반복해 보내 성공 가능성을 높이는 것이 알려진 공격 전개 방식이다."
  },
  {
    "name": "알려진 취약점 점검 도구의 흔적과 악용 구문 동반",
    "technique": "T1190",
    "weakness": "CVE-2021-44228",
    "match": {
      "description": "알려진 취약점 점검 흔적이 CVE-2021-44228 형태 악용 구문과 함께 나타난다. 점검 도구 이름만 있거나 수업용 프로그램 이름만 있는 경우는 맞추지 않는다.",
      "descriptionAll": ["알려진 취약점 점검 흔적"],
      "descriptionAny": ["CVE-2021-44228 형태가 함께"],
      "descriptionNone": ["비슷한 수업용", "이름이 로그에", "이름 검색"]
    },
    "evidence": "MITRE ATT&CK T1190: 공격자는 악용 전에 nuclei·nikto 같은 취약점 점검 도구로 대상을 훑고, 그 흔적이 실제 악용 구문과 함께 관측되면 표적 악용 정황으로 본다."
  }
];

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const TECHNIQUE = 'T1190';
// 공격 구문은 없지만 Wazuh 규칙이 T1190 으로 표시한 단발 요청: 사람이 볼 수 있게 alert 까지만 올린다.
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

// 한 패턴이 경보 설명과 맞는지 본다. All 은 모두 포함, Any 는 하나 이상 포함, None 은 하나도 없어야 한다.
function matchPattern(pattern, description, count) {
  const m = pattern.match;
  const all = m.descriptionAll ?? [];
  const any = m.descriptionAny ?? [];
  const none = m.descriptionNone ?? [];

  if (!all.every((phrase) => description.includes(phrase))) return 0;
  if (none.some((phrase) => description.includes(phrase))) return 0;
  if (any.length > 0 && !any.some((phrase) => description.includes(phrase))) return 0;

  // 반복 패턴(countField 가 있는 것): 횟수로 점수를 매긴다.
  if (m.countField) {
    return scale(Math.max(count, 1), m.weakAtLeast, m.strongAtLeast);
  }
  // 구문 패턴: 조건이 맞으면 뚜렷한 악용으로 본다.
  return 0.9;
}

export function decide(alert) {
  const description = String(alert?.rule?.description ?? '');
  const count = toCount(alert?.data?.count);
  const tagged = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes(TECHNIQUE);

  const hits = PATTERNS.map((pattern) => ({ pattern, score: matchPattern(pattern, description, count) }))
    .filter((h) => h.score > 0)
    .sort((a, b) => b.score - a.score);

  if (hits.length > 0) {
    // 서로 다른 악용 신호(구문 + 반복 + 점검 흔적)가 함께 나오면 조금 더 뚜렷하다고 본다.
    const bonus = Math.min(0.06, (hits.length - 1) * 0.03);
    const confidence = Math.round(Math.min(0.99, hits[0].score + bonus) * 100) / 100;
    const action = confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record';
    const names = hits.map((h) => h.pattern.name + '(' + h.pattern.technique + ', ' + h.pattern.weakness + ')').join(' + ');
    return { action, confidence, reason: names };
  }

  // 패턴에 안 맞지만 Wazuh 가 T1190 으로 표시했고 경보 수준이 높으면(악용 의심) 사람이 보게 alert.
  const level = Number(alert?.rule?.level ?? 0);
  if (tagged && level >= 10) {
    return {
      action: 'alert',
      confidence: TAGGED_ONLY_SCORE,
      reason: '외부 공개 앱 악용 표시(' + TECHNIQUE + ')에 높은 경보 수준이나 구문 패턴 표기는 뚜렷하지 않음',
    };
  }

  return { action: 'record', confidence: 0, reason: '일치하는 알려진 취약점 악용 패턴 없음' };
}

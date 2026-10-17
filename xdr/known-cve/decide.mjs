// xdr/known-cve/decide.mjs
// 알려진 취약점 악용(CVE-2021-44228 / Log4Shell) 경보 판단기.
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부른다.
// 규칙: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않는다. 이 파일 안에서 혼자 계산한다.
// 판단 결과만 돌려준다. 알림 기록과 판정기 연결은 respond.mjs 에서 한다.
//
// 핵심: 설명 문구가 아니라 경보의 "실제 요청 신호"(data.useragent, data.url)에서
//       원격 조회 구문 ${jndi:...} 자체를 찾는다. T1190 태그나 경보 수준만으로는 올리지 않는다.

// xdr/known-cve/patterns.json 의 patterns 를 그대로 옮겨 적은 상수 (근거: CVE-2021-44228, MITRE ATT&CK T1190)
export const PATTERNS = [
  {
    "name": "요청 머리글·주소 인자 안의 원격 조회 구문(jndi 형태)",
    "technique": "T1190",
    "weakness": "CVE-2021-44228",
    "match": {
      "signal": "경보의 실제 요청 신호(data.useragent, data.url)에 ${jndi:...} 형태의 원격 조회 구문이 들어 있다.",
      "fields": ["data.useragent", "data.url"],
      "exploitRegex": "\\$\\{jndi:",
      "action": "block"
    },
    "evidence": "CVE-2021-44228(Log4Shell): 요청 머리글·인자에 ${jndi:ldap://...} 형태의 원격 조회 구문을 넣어 취약한 Log4j가 외부 주소에서 코드를 끌어오게 만드는 것이 대표적 악용 방식이다."
  },
  {
    "name": "악용 구문 없이 취약점 이름·jndi 단어만 등장",
    "technique": "T1190",
    "weakness": "CVE-2021-44228",
    "match": {
      "signal": "요청 값에 원격 조회 구문은 없지만 취약점 이름('CVE-2021-44228')이나 'jndi' 단어, 잘린 조회 형태가 검색어·경로에 나타난다.",
      "fields": ["data.useragent", "data.url"],
      "nameRegex": "cve-2021-44228|jndi|lookup-fragment",
      "requireNoExploit": true,
      "action": "alert"
    },
    "evidence": "MITRE ATT&CK T1190: 실제 악용 구문 없이 취약점 이름만 조회하거나 jndi 단어만 흘리는 것은 정찰·시험 단계일 수 있어 차단까지 하지 않고 사람이 보도록 알림만 올린다."
  }
];

// 요청 값에서 ${jndi:...} 형태의 원격 조회 구문을 찾는다(대소문자 무시).
const EXPLOIT_RE = /\$\{jndi:/i;
// 악용 구문은 없지만 취약점 이름·단어가 나오는지 본다.
const NAME_RE = /cve-2021-44228|jndi|lookup-fragment/i;

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

// 경보에서 실제 요청 신호 텍스트만 모은다(설명은 쓰지 않는다). 원격 조회 주소 등 값은 판단에만 쓰고 reason 에 넣지 않는다.
function requestSignals(alert) {
  const d = alert?.data ?? {};
  return [d.useragent, d.url].map((v) => String(v ?? '')).join(' ');
}

export function decide(alert) {
  const signal = requestSignals(alert);

  // 1) 실제 원격 조회 구문이 요청에 들어 있으면 형태가 뚜렷한 악용 → block.
  if (EXPLOIT_RE.test(signal)) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: PATTERNS[0].name + '(' + PATTERNS[0].technique + ', ' + PATTERNS[0].weakness + ')',
    };
  }

  // 2) 구문은 없지만 취약점 이름·jndi 단어·잘린 형태가 요청에 보이면 애매한 시도 → alert.
  if (NAME_RE.test(signal)) {
    return {
      action: 'alert',
      confidence: 0.6,
      reason: PATTERNS[1].name + '(' + PATTERNS[1].technique + ', ' + PATTERNS[1].weakness + ')',
    };
  }

  // 3) 그 밖은 정상 이벤트 → record.
  return { action: 'record', confidence: 0, reason: '요청 신호에 알려진 취약점 악용 흔적 없음' };
}

// xdr/persistence/decide.mjs
// 몰래 심어진 프로그램(지속성) 경보 판단기.
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부른다.
// 규칙: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않는다. 이 파일 안에서 혼자 계산한다.
// 판단 결과만 돌려준다. 알림 기록과 판정기 연결은 respond.mjs 에서 한다.
//
// 세 유형 구분:
//  - block: 서명 없는 새 서비스/예약 작업이 임시 폴더를 가리키거나 평소 목록에 없는 시작 항목이 추가된 뚜렷한 지속성.
//  - alert: 수업용 경로에 새 항목이지만 서명 미확인·단발 등 애매한 시도(경보 수준이 올라가 있음).
//  - record: 로그인·서명된 기존 서비스·평소 예약 작업 등 정상 이벤트.

// xdr/persistence/patterns.json 의 patterns 를 그대로 옮겨 적은 상수 (근거: MITRE ATT&CK T1543, T1053)
export const PATTERNS = [
  {
    "name": "서명 없는 새 서비스가 임시 폴더를 가리킴",
    "technique": "T1543",
    "match": {
      "descriptionAny": ["서명 없는 새 서비스", "서비스 실행 파일이 바뀌었고 서명이 없", "평소 목록에 없는 서비스가 다시 켜도 남", "서명 없는 서비스 등록"],
      "action": "block"
    },
    "evidence": "MITRE ATT&CK T1543: 서명 없는 실행 파일을 가리키는 새 서비스를 등록해 재부팅 뒤에도 남는 지속성을 확보한다."
  },
  {
    "name": "처음 보는 예약 작업이 임시 폴더 프로그램을 실행",
    "technique": "T1053",
    "match": {
      "descriptionAny": ["처음 보는 예약 작업이 임시 폴더", "예약 작업 이름이 임의 문자열이고 실행 파일이 임시 폴더"],
      "action": "block"
    },
    "evidence": "MITRE ATT&CK T1053: 임의 이름의 예약 작업으로 임시 폴더 프로그램을 비업무 시간에 실행시켜 지속성·은닉을 얻는다."
  },
  {
    "name": "시작 폴더·시작 항목에 평소 목록에 없는 프로그램 추가",
    "technique": "T1543",
    "match": {
      "descriptionAny": ["시작 폴더에 평소 목록에 없는 프로그램", "시작 프로그램과 예약 작업이 같은 임시 파일"],
      "action": "block"
    },
    "evidence": "MITRE ATT&CK T1543: 시작 폴더·시작 항목에 평소 목록에 없는 프로그램이 추가되면 로그인마다 자동 실행돼 지속성이 생긴다."
  }
];

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
// 수업용 경로 새 항목이지만 서명 미확인·단발인 애매한 시도는 경보 수준이 이 구간이다. 정상(로그인·기존 서명)은 그 아래.
const AMBIGUOUS_LEVEL = 5;

export function decide(alert) {
  const description = String(alert?.rule?.description ?? '');
  const level = Number(alert?.rule?.level ?? 0);

  // 1) 패턴(뚜렷한 지속성 신호)과 맞으면 block.
  const hit = PATTERNS.find((p) => p.match.descriptionAny.some((phrase) => description.includes(phrase)));
  if (hit) {
    return {
      action: 'block',
      confidence: 0.95,
      reason: hit.name + '(' + hit.technique + ')',
    };
  }

  // 2) 패턴에 안 맞지만 경보 수준이 애매 구간 이상이면(수업용 새 항목·서명 미확인·단발 등) alert.
  if (level >= AMBIGUOUS_LEVEL) {
    return {
      action: 'alert',
      confidence: 0.6,
      reason: '평소 목록에 없는 지속성 항목이나 서명·실행 근거가 뚜렷하지 않음(T1543/T1053)',
    };
  }

  // 3) 그 밖(로그인·서명된 기존 서비스·평소 예약 작업 등 낮은 수준)은 정상 → record.
  return { action: 'record', confidence: 0, reason: '평소 목록·서명된 기존 항목 등 정상 이벤트' };
}

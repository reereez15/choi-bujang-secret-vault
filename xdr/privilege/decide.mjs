// xdr/privilege/decide.mjs
// 권한 가로채기(권한 상승·계정 도용) 경보 판단기.
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부른다.
// 규칙: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않는다. 이 파일 안에서 혼자 계산한다.
// 판단 결과만 돌려준다. 알림 기록과 판정기 연결은 respond.mjs 에서 한다.
//
// 세 유형:
//  - block: 관리자 그룹 추가 + 원격/처음 보는 주소/곧바로 명령, 낯선 주소·비업무 시각의 관리자 명령·권한 상승 등 뚜렷한 가로채기.
//  - alert: 수업·과제 그룹 추가, 평소 주소 단발 관리자 명령, 권한 상승 취소·실패 등 애매한 시도(경보 수준이 올라가 있음).
//  - record: 로그인·그룹 조회·비밀번호 변경·수업용 관리 계정의 평소 활동 등 정상 이벤트.

// xdr/privilege/patterns.json 의 patterns 를 그대로 옮겨 적은 상수 (근거: MITRE ATT&CK T1068, T1078)
export const PATTERNS = [
  {
    "name": "관리자 그룹 추가와 곧바로 이어진 권한 사용",
    "technique": "T1078",
    "match": {
      "descriptionAny": ["원격 주소에서 관리자 그룹에 추가", "관리자 그룹에 들어가고 곧바로 권한", "관리자 그룹 추가와 명령 실행이 같이", "관리자 그룹에 추가됐습니다", "다시 관리자로 들어왔습니다"],
      "action": "block"
    },
    "evidence": "MITRE ATT&CK T1078: 탈취·생성한 정상 계정을 관리자 그룹에 넣어 권한을 위장하고 곧바로 관리 작업을 수행한다."
  },
  {
    "name": "처음 보는 주소·비업무 시각의 관리자 명령/권한 변경",
    "technique": "T1068",
    "match": {
      "descriptionAny": ["처음 보는 주소에서 관리자 명령", "관리자 권한으로 바뀌었고 요청 주소는 처음", "다른 계정의 권한으로 관리자 명령", "관리자가 된 user01 이 관리자 명령을 실행"],
      "action": "block"
    },
    "evidence": "MITRE ATT&CK T1068: 권한을 올린 공격자가 낯선 주소·비업무 시각에 관리자 명령을 실행하거나 세션 권한을 상승시켜 통제권을 확보한다."
  }
];

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
// 애매한 시도(수업·과제 그룹, 평소 주소 단발 명령, 취소·실패)는 경보 수준이 이 구간이다. 정상(로그인·조회·평소 활동)은 그 아래.
const AMBIGUOUS_LEVEL = 5;

export function decide(alert) {
  const description = String(alert?.rule?.description ?? '');
  const level = Number(alert?.rule?.level ?? 0);

  // 1) 패턴(뚜렷한 권한 가로채기)과 맞으면 block.
  const hit = PATTERNS.find((p) => p.match.descriptionAny.some((phrase) => description.includes(phrase)));
  if (hit) {
    return { action: 'block', confidence: 0.95, reason: hit.name + '(' + hit.technique + ')' };
  }

  // 2) 패턴에 안 맞지만 경보 수준이 애매 구간 이상이면(수업 그룹·단발 명령·취소·실패 등) alert.
  if (level >= AMBIGUOUS_LEVEL) {
    return {
      action: 'alert',
      confidence: 0.6,
      reason: '권한 관련 변화가 있으나 관리자 그룹 도용·낯선 주소 근거가 뚜렷하지 않음(T1068/T1078)',
    };
  }

  // 3) 그 밖(로그인·조회·비밀번호 변경·평소 관리 계정 등 낮은 수준)은 정상 → record.
  return { action: 'record', confidence: 0, reason: '로그인·조회·평소 권한 사용 등 정상 이벤트' };
}

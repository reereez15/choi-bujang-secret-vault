// xdr/exfiltration/decide.mjs
// 자료 빼돌리기(유출) 경보 판단기.
// 심판은 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부른다.
// 규칙: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않는다. 이 파일 안에서 혼자 계산한다.
// 판단 결과만 돌려준다. 알림 기록과 판정기 연결은 respond.mjs 에서 한다.
//
// 세 유형:
//  - block: 처음 보는 목적지로 대용량·대량 자료 반출, 같은 목적지 반복·업무 밖 연속 전송 등 뚜렷한 유출.
//  - alert: 중간 크기 단발·수업 자료 주소·실패·백업처럼 보이는 전송 등 애매한 시도(경보 수준이 올라가 있음).
//  - record: 메모 읽기·공지·새로고침·평소 목적지 소량 동기화 등 정상 이벤트.

// xdr/exfiltration/patterns.json 의 patterns 를 그대로 옮겨 적은 상수 (근거: MITRE ATT&CK T1041, T1048)
export const PATTERNS = [
  {
    "name": "처음 보는 목적지로 대용량·대량 자료 전송",
    "technique": "T1048",
    "match": {
      "descriptionAny": ["처음 보는 목적지로 나갔습니다", "처음 보는 주소로 나갔습니다", "처음 보는 목적지로 메모 묶음이 한 번에", "자료실 전체가 외부 주소로 복사", "처음 보는 목적지 두 곳으로 같은 압축 파일", "처음 보는 주소에 올라갔습니다"],
      "action": "block"
    },
    "evidence": "MITRE ATT&CK T1048: 평소 쓰지 않던 목적지·프로토콜로 수집한 자료를 대량·대용량으로 내보내 유출한다."
  },
  {
    "name": "같은 목적지로 대용량 전송 반복·업무 밖 연속 반출",
    "technique": "T1041",
    "match": {
      "descriptionAny": ["대용량 전송이 8번 반복", "같은 목적지로 전송이 15번", "명령 통로로 큰 파일이 처음 보는 목적지에 반복", "평소에 쓰지 않던 포트로 자료 이름이 연속"],
      "action": "block"
    },
    "evidence": "MITRE ATT&CK T1041: 명령·제어 통로로 자료를 여러 번 나눠 반복 전송해 유출하며, 업무 밖 연속 대용량 전송은 자동화된 반출 정황이다."
  }
];

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
// 애매한 시도(중간 크기 단발·수업 자료 주소·실패·백업)는 경보 수준이 이 구간이다. 정상(소량 조회·평소 동기화)은 그 아래.
const AMBIGUOUS_LEVEL = 5;

export function decide(alert) {
  const description = String(alert?.rule?.description ?? '');
  const level = Number(alert?.rule?.level ?? 0);

  // 1) 패턴(뚜렷한 유출 신호)과 맞으면 block.
  const hit = PATTERNS.find((p) => p.match.descriptionAny.some((phrase) => description.includes(phrase)));
  if (hit) {
    return { action: 'block', confidence: 0.95, reason: hit.name + '(' + hit.technique + ')' };
  }

  // 2) 패턴에 안 맞지만 경보 수준이 애매 구간 이상이면(중간 크기 단발·수업 주소·실패 등) alert.
  if (level >= AMBIGUOUS_LEVEL) {
    return {
      action: 'alert',
      confidence: 0.6,
      reason: '평소와 다른 전송이 있으나 처음 보는 목적지·대용량·반복 근거가 뚜렷하지 않음(T1041/T1048)',
    };
  }

  // 3) 그 밖(소량 조회·공지·새로고침·평소 목적지 등 낮은 수준)은 정상 → record.
  return { action: 'record', confidence: 0, reason: '소량 조회·평소 목적지 동기화 등 정상 이벤트' };
}

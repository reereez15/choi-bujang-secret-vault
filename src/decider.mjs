// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 6단계: 등록된 기기(request.deviceRegistered === true)일 때만 내 자료실 읽기를 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
// 계약(docs/DECIDER_REQUEST.md)에 있는 값만 씁니다. request.device 같은 값은 없습니다.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  // 규칙 device_registered: 값이 정확히 true일 때만 허용합니다.
  // false, 값 없음, 문자열 "true" 같은 다른 모양은 모두 미등록으로 보고 거부합니다.
  if (request?.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}

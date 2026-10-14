// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 계약(docs/DECIDER_REQUEST.md)에 있는 18개 이름만 읽습니다.
// request.role, request.identity, request.device, request.geo는 계약에 없으므로 읽지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

const response = (request, decision, reasonCode, ruleIds) => ({
  schema: 'aleph.decision.v1',
  requestId: request?.requestId,
  decision,
  reasonCode,
  ruleIds,
});

// 사유 기록용 로거(테스트에서는 DECIDER_QUIET=1로 끌 수 있다). 토큰·본문은 기록하지 않는다.
const log = (message) => { if (process.env.DECIDER_QUIET !== '1') process.stderr.write(`${message}\n`); };

// 계약: signals = {source, region, network, hour}, recentEvents = [{kind, ageSeconds, count}].
// 제작 2 지시: "평소와 다른 시각과 처음 보는 네트워크에서 갑자기 많은 자료를 읽는" 사건만 추가 확인.
// 즉 복합 사건의 축은 정확히 세 가지다: (1) 평소와 다른 시각, (2) 처음 보는 네트워크, (3) 대량 읽기.
// 지역(region)은 추가 확인 조건으로 쓰지 않는다(지역 하나만으로 차단하지 말라는 지시).
// 모르는 값을 이상으로 보지 않는다. 명확히 "다름"을 가리키는 값만 이상으로 센다. "unknown"은 제외.
const ABNORMAL_NETWORKS = new Set(['unusual', 'new', 'untrusted', 'public', 'tor', 'vpn', 'anomalous', 'foreign']);
const BULK_READ_COUNT = 10;
const lc = (v) => (typeof v === 'string' ? v.trim().toLowerCase() : null);
// 세 축이 각각 이상인지 본다.
function abnormalHour(s) {
  const h = Number.isInteger(s?.hour) && s.hour >= 0 && s.hour <= 23 ? s.hour : null;
  return h !== null && (h < 6 || h >= 22);          // 밤~새벽
}
function abnormalNetwork(s) {
  return ABNORMAL_NETWORKS.has(lc(s?.network));      // 처음 보는 네트워크
}
function bulkRead(request) {
  const events = Array.isArray(request?.recentEvents) ? request.recentEvents.slice(0, 12) : [];
  return events.some((e) => e && Number.isInteger(e.count) && e.count >= BULK_READ_COUNT);
}

// 계약: stepUp = {verified, authAgeSeconds}. verified가 참이면 최근 재인증을 마친 것으로 본다.
// verified가 참이어도 나이가 숫자로 함께 오면 범위(0~900초)를 확인한다.
function recentlyVerified(request) {
  const su = request?.stepUp;
  if (su?.verified !== true) return false;
  const age = su.authAgeSeconds;
  if (typeof age === 'number' && Number.isFinite(age)) return age >= 0 && age <= 900;
  return true;
}

export async function decide(request) {
  // 규칙 device_registered(6단계): 등록 기기만 통과, 미등록·값 없음은 거부.
  if (request?.deviceRegistered !== true) {
    return response(request, 'deny', 'device_not_registered', ['device_registered']);
  }

  // 규칙 step_up_required(7단계): 평소와 다른 시각 AND 처음 보는 네트워크 AND 대량 읽기가
  // 모두 함께일 때만 추가 확인(step_up)을 요청한다. 지역은 조건으로 쓰지 않고 영구 차단(deny)도 하지 않는다.
  const s = request?.signals;
  const unusual = abnormalHour(s) && abnormalNetwork(s) && bulkRead(request);
  if (unusual) {
    // 이미 최근에 재인증을 마친 요청이면(계약의 stepUp) 다시 확인을 요구하지 않고 통과시킨다.
    if (recentlyVerified(request)) {
      log('decider: 평소와 다른 접속이지만 최근 재인증이 확인되어 통과합니다.');
      return response(request, 'allow', 'approved', ['device_registered']);
    }
    log('decider: 평소와 다른 시각·네트워크·대량읽기가 겹쳐 추가 확인을 요청합니다.');
    return response(request, 'step_up', 'step_up_required', ['step_up_required']);
  }

  return response(request, 'allow', 'approved', ['device_registered']);
}

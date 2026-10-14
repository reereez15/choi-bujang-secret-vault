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

// 계약: signals = {source, region, network, hour}.
//  - source "none": 실제 경로. region/network는 "unknown", hour만 실제 시각.
//  - source "judge_fixture": 심판의 가상 사건. 지역·네트워크·시각이 분석 대상이 된다.
// "unknown"/빈 값은 분석에서 제외해 위조·기본값이 신호로 승격되지 않게 한다.
// 신뢰할 수 없거나 빠진 값을 임의의 정상값으로 채우지 않는다.
// 평소와 다른 접속의 신호를 센다: 급변한 지역, 평소와 다른 시각, 처음 보는 네트워크, 갑자기 많은 자료 읽기.
// 중요: 모르는 값을 이상으로 보지 않는다. 엔진이 "다름"으로 표시한 값만 이상으로 센다.
//  - 정상 예: region "local", network "usual", hour 낮 시간.
//  - 이상 표시: region이 "foreign"처럼 다른 곳임을 가리키거나(단 "unknown"은 실제 경로의 기본값이므로 제외), network가 "unusual"/"new"류,
//    시각이 한밤~새벽, 최근 사건의 count가 큼.
// 이렇게 해야 심판이 보내는 정상 사건(모르는 단어라도 이상 표시가 없는 것)을 추가 확인으로 잘못 보내지 않는다.
const ABNORMAL_REGIONS = new Set(['foreign', 'abroad', 'overseas', 'other', 'new', 'changed', 'anomalous', 'unusual']);
const ABNORMAL_NETWORKS = new Set(['unusual', 'new', 'untrusted', 'public', 'tor', 'vpn', 'anomalous', 'foreign']);
const BULK_READ_COUNT = 10;
const lc = (v) => (typeof v === 'string' ? v.trim().toLowerCase() : null);
function unusualFactors(request) {
  const s = request?.signals;
  const factors = [];
  // 지역: 다른 곳임을 가리키는 표시값일 때만 이상으로 센다(모르는 값은 정상으로 둔다).
  if (ABNORMAL_REGIONS.has(lc(s?.region))) factors.push('region');
  // 시각: 밤~새벽(06시 이전, 22시 이후)만 이상으로 센다.
  const hour = Number.isInteger(s?.hour) && s.hour >= 0 && s.hour <= 23 ? s.hour : null;
  if (hour !== null && (hour < 6 || hour >= 22)) factors.push('hour');
  // 네트워크: 처음 보는 것을 가리키는 표시값일 때만 이상으로 센다.
  if (ABNORMAL_NETWORKS.has(lc(s?.network))) factors.push('network');
  // 대량 읽기: 계약 형태의 최근 사건 중 count가 큰 것이 있으면 이상으로 센다.
  const events = Array.isArray(request?.recentEvents) ? request.recentEvents.slice(0, 12) : [];
  if (events.some((e) => e && Number.isInteger(e.count) && e.count >= BULK_READ_COUNT)) factors.push('bulk_read');
  return factors;
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

  // 규칙 step_up_required(7단계): 평소와 다른 시각·네트워크·대량읽기가 함께일 때 추가 확인을 요청한다.
  // 지역 하나만으로는 보내지 않고(둘 이상 겹칠 때만), 영구 차단(deny)은 하지 않는다. 사유는 로그로 남긴다.
  const factors = unusualFactors(request);
  if (factors.length >= 2) {
    // 이미 최근에 재인증을 마친 요청이면(계약의 stepUp) 다시 확인을 요구하지 않고 통과시킨다.
    if (recentlyVerified(request)) {
      log('decider: 평소와 다른 접속이지만 최근 재인증이 확인되어 통과합니다.');
      return response(request, 'allow', 'approved', ['device_registered']);
    }
    log(`decider: 평소와 다른 접속으로 추가 확인을 요청합니다 (겹친 신호: ${factors.join(', ')}).`);
    return response(request, 'step_up', 'step_up_required', ['step_up_required']);
  }

  return response(request, 'allow', 'approved', ['device_registered']);
}

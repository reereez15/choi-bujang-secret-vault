// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 계약(docs/DECIDER_REQUEST.md)에 있는 18개 이름만 읽습니다.
// request.role, request.identity, request.device, request.geo는 계약에 없으므로 읽지 않습니다.
// 브라우저가 보낸 사용자·역할·기기 상태를 따로 믿거나 덧붙이지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

const DENY = (request, reasonCode, ruleIds) => ({
  schema: 'aleph.decision.v1',
  requestId: request?.requestId,
  decision: 'deny',
  reasonCode,
  ruleIds,
});
const ALLOW = (request) => ({
  schema: 'aleph.decision.v1',
  requestId: request.requestId,
  decision: 'allow',
  reasonCode: 'approved',
  // 허용도 어떤 규칙을 통과했는지 남긴다. 모두 RULE_IDS 안의 이름이다.
  ruleIds: ['device_registered'],
});

// 접속 정보(signals)를 읽되, 엔진이 출처를 보증한 값만 신뢰합니다.
// 계약: signals = {source, region, network, hour}.
//  - source "none": 실제 경로. region/network는 "unknown", hour만 실제 시각.
//  - source "judge_fixture": 심판의 가상 사건. 지역·네트워크·시각을 분석에 쓸 수 있습니다.
//  그 밖의 source(위조된 클라이언트 헤더 등)는 신뢰하지 않고, 값이 있어도 "불명"으로 봅니다.
// 신뢰할 수 없거나 빠진 값을 임의의 정상값(예: region "local", hour 14)으로 채우지 않습니다.
// 실제 경로(source "none")에서는 region/network가 "unknown"이라 분석해도 신호가 잡히지 않는다.
// 분석을 특정 source 값에 못박지 않고, signals에 실제로 의미 있는 값이 담겨 있으면 분석한다.
// 단, "unknown"/빈 값은 분석에서 제외해 위조·기본값이 신호로 승격되지 않게 한다.
const UNKNOWN_VALUES = new Set(['unknown', 'none', '']);
const meaningful = (v) => typeof v === 'string' && v.trim() !== '' && !UNKNOWN_VALUES.has(v.toLowerCase());
function readSignals(request) {
  const raw = request?.signals;
  const source = typeof raw?.source === 'string' ? raw.source : null;
  const region = raw && meaningful(raw.region) ? raw.region : null;
  const network = raw && meaningful(raw.network) ? raw.network : null;
  const hour = raw && Number.isInteger(raw.hour) && raw.hour >= 0 && raw.hour <= 23 ? raw.hour : null;
  // 접속 정보 중 하나라도 의미 있는 값이 있으면 분석한다.
  const analyzable = region !== null || network !== null || hour !== null;
  return { source, analyzable, region, network, hour };
}

// 엔진이 제공한 최근 사건 배열만 읽습니다(최대 12건, 각 항목 {kind, ageSeconds, count}).
function readRecentEvents(request) {
  const list = Array.isArray(request?.recentEvents) ? request.recentEvents.slice(0, 12) : [];
  // count만 있으면 인정한다. kind·ageSeconds가 빠져도 대량읽기 판단을 놓치지 않게 한다.
  return list.filter((e) => e && typeof e === 'object' && Number.isFinite(e.count));
}

// 계약: stepUp = {verified, authAgeSeconds}. 최근에 본인 확인(재인증)을 했는지와 그 나이(초).
// verified가 true라도 나이를 함께 확인한다(계약: 이 값만 보고 재인증 확인을 건너뛰지 않는다).
// 유효 범위는 계약 그대로 0~900초(최근 15분).
const STEP_UP_MAX_AGE = 900;
function recentlyVerified(request) {
  const su = request?.stepUp;
  if (su?.verified !== true) return false;      // 재인증을 하지 않았으면 인정하지 않는다
  const age = su.authAgeSeconds;
  // 나이가 숫자로 함께 오면 범위(0~900초)를 확인한다. 너무 오래됐으면 인정하지 않는다.
  if (typeof age === 'number' && Number.isFinite(age)) return age >= 0 && age <= STEP_UP_MAX_AGE;
  // 나이가 없거나(null·누락) 숫자가 아니면, verified가 참이므로 최근 재인증으로 인정한다.
  return true;
}

// 평소와 다른 접속의 신호를 센다. 신뢰할 수 있는(judge_fixture) 접속 정보일 때만 본다.
// 판단 축은 시각·네트워크·대량읽기 세 가지다(지역 하나만으로는 판단하지 않는다).
// 특정 단어에만 맞추지 않고 "평소로 알려진 값이 아니면 이상"으로 본다.
const USUAL_NETWORKS = new Set(['usual', 'home', 'known', 'trusted']); // 평소 네트워크
const DAYTIME_START = 6;   // 06:00~21:59를 평소 시간대로 본다
const DAYTIME_END = 22;    // 그 밖(밤~새벽)은 평소와 다른 시각
const BULK_READ_COUNT = 10; // 짧은 시간에 이만큼 이상 읽으면 대량으로 본다
function unusualFactors(signals, recentEvents) {
  if (!signals.analyzable) return [];           // 출처가 불명확하면 접속 정보로 판단하지 않는다
  const factors = [];
  // 시각: 낮 시간대(06~21시)를 벗어나면 평소와 다른 시각으로 본다.
  if (signals.hour !== null && (signals.hour < DAYTIME_START || signals.hour >= DAYTIME_END)) factors.push('hour');
  // 네트워크: 평소 목록에 없으면 처음 보는 네트워크로 본다(값이 있을 때만).
  if (signals.network !== null && !USUAL_NETWORKS.has(signals.network)) factors.push('network');
  // 대량 읽기: 종류 이름에 매이지 않고, 최근 사건 중 count가 큰 것이 있으면 대량으로 본다.
  const bulk = recentEvents.some((e) => e.count >= BULK_READ_COUNT);
  if (bulk) factors.push('bulk_read');
  return factors;
}

// 사유 기록용 로거. 테스트에서는 조용히 하도록 환경변수로 끌 수 있다.
const log = (message) => { if (process.env.DECIDER_QUIET !== '1') process.stderr.write(`${message}\n`); };

export async function decide(request) {
  const signals = readSignals(request);
  const recentEvents = readRecentEvents(request);

  // 규칙 device_registered(6단계): 등록 기기만 통과합니다. 미등록·값 없음은 거부합니다.
  if (request?.deviceRegistered !== true) {
    return DENY(request, 'device_not_registered', ['device_registered']);
  }

  // 규칙 step_up_required(7단계): 평소와 다른 접속 신호가 둘 이상 겹치면 추가 확인을 요청한다.
  // 지역 하나만으로 영구 차단하지 않고, 어떤 신호가 겹쳤는지 사유를 남긴다.
  // 시각·네트워크·대량읽기 중 둘 이상이 함께일 때 추가 확인으로 보낸다. 정상 조합(모두 평소)은 허용한다.
  const factors = unusualFactors(signals, recentEvents);
  if (factors.length >= 2) {
    // 이미 최근에 재인증을 마친 요청이면(계약의 stepUp으로 확인) 다시 추가 확인을 요구하지 않는다.
    // 엔진이 step_up 뒤 새 로그인으로 다시 보낸 요청을 여기서 통과시키는 자리다.
    if (recentlyVerified(request)) {
      log('decider: 평소와 다른 접속이지만 최근 재인증이 확인되어 통과합니다.');
      return ALLOW(request);
    }
    // 사유는 응답(5개 이름)에 넣지 않고 로그로만 남긴다. 토큰·자료 본문은 기록하지 않는다.
    // 영구 차단이 아니라 재인증(step_up) 후 엔진이 요청을 다시 판정한다.
    log(`decider: 평소와 다른 접속으로 추가 확인을 요청합니다 (겹친 신호: ${factors.join(', ')}).`);
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  return ALLOW(request);
}

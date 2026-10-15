// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 계약(docs/DECIDER_REQUEST.md)에 있는 18개 이름만 읽습니다.
// request.role, request.identity, request.device, request.geo는 계약에 없으므로 읽지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'zone_policy']);

const response = (request, decision, reasonCode, ruleIds) => ({
  schema: 'aleph.decision.v1',
  requestId: request?.requestId,
  decision,
  reasonCode,
  ruleIds,
});

// 사유 기록용 로거(테스트에서는 DECIDER_QUIET=1로 끌 수 있다). 토큰·본문은 기록하지 않는다.
const log = (message) => {
  // 심판·엔진 실행 환경에는 Node의 process가 없을 수 있다. 사유 기록이 판정을 멈추면 안 되므로
  // process가 있을 때만 적고, 어떤 경우에도 예외를 밖으로 내보내지 않는다.
  try {
    const p = typeof process !== 'undefined' ? process : undefined;
    if (p?.env?.DECIDER_QUIET === '1') return;
    p?.stderr?.write?.(`${message}\n`);
  } catch { /* 기록 실패는 무시한다 */ }
};

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

// 8단계: 요청을 서비스와 경로 모양으로 세 구역과 동작으로 분류한다(읽기 전용).
// 계약의 service·method·route·path만 쓴다. 요청 본문의 role·owner는 읽지 않는다.
// 계약 예시: route = "GET /notes/:id" (서비스 앞의 /api 접두사는 있을 수도 없을 수도 있다).
// 구역: 'memo'(내 메모), 'notice'(반 공지), 'instructor'(강사 자료), null(알 수 없음).
// 경로 정보가 아예 없으면(route·path·service 모두 없음) 구역 판단을 하지 않는다(null과 구분해 skip).
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
function classify(request) {
  const method = typeof request?.method === 'string' ? request.method.toUpperCase() : null;
  const route = typeof request?.route === 'string' ? request.route.trim() : '';
  const path = typeof request?.path === 'string' ? request.path.trim() : '';
  const service = typeof request?.service === 'string' ? request.service.trim().toLowerCase() : '';
  // 경로 정보가 전혀 없으면 구역 규칙을 적용할 수 없다(6·7단계 전용 연습 요청 등).
  const hasRouteInfo = route !== '' || path !== '' || service !== '';
  if (!hasRouteInfo) return { present: false };

  // 판정에 쓸 경로 모양: route가 있으면 route, 없으면 "METHOD path"로 만든다.
  const shape = route || `${method ?? ''} ${path}`.trim();
  // 경로 부분만 뽑아 앞의 /api를 떼고 비교한다(계약 예시가 /notes/:id 형태).
  const pathPart = (shape.split(/\s+/).pop() || '').replace(/^\/api(?=\/)/, '');
  const isWrite = method !== null && WRITE_METHODS.has(method);

  // 정확한 경로 모양만 인정한다(넓은 startsWith 금지). service도 함께 본다.
  const MY_NOTES_ITEM = /^\/(my\/notes|notes)\/:id$/;   // 내 메모 단건
  const MY_NOTES_LIST = /^\/my\/notes$/;                 // 내 목록(명시적)
  const OLD_NOTES_LIST = /^\/notes$/;                     // 옛 전체 목록(거부 대상)
  const NOTICE = /^\/announcements(\/:id)?$/;             // 반 공지
  const INSTRUCTOR = /^\/instructor(\/[^/]+)?$/;          // 강사 자료
  const RESTORE = /^\/restore\/note$/;                     // 메모 복원 경로(메서드는 아래서 POST만 인정)
  const DEVICE_CHECK = /^\/device\/check$/;                 // 기기 승인 확인(로그인·권한만, 자료 없음)

  let zone = null;        // 'memo' | 'notice' | 'instructor' | null(미등록 경로)
  let kind = 'unknown';   // 'item' | 'list'
  if (MY_NOTES_ITEM.test(pathPart)) { zone = 'memo'; kind = 'item'; }
  else if (MY_NOTES_LIST.test(pathPart)) { zone = 'memo'; kind = 'list'; }
  else if (OLD_NOTES_LIST.test(pathPart)) { zone = 'memo'; kind = 'list'; }
  else if (NOTICE.test(pathPart)) { zone = 'notice'; kind = /:id/.test(pathPart) ? 'item' : 'list'; }
  else if (INSTRUCTOR.test(pathPart)) { zone = 'instructor'; kind = 'item'; }
  else if (RESTORE.test(pathPart)) {
    // 복원은 POST만 인정한다. 그 밖 메서드는 미등록 경로로 두어 거부되게 한다.
    if (method === 'POST') { zone = 'memo'; kind = 'item'; }
  }
  else if (DEVICE_CHECK.test(pathPart)) {
    // 기기 승인 확인은 GET만 인정한다(자료를 돌려주지 않는 확인 전용).
    if (method === 'GET') { zone = 'memo'; kind = 'item'; }
  }
  // service가 note류인데 경로가 안 맞으면(예: 기능 경로) zone은 null로 남겨 거부되게 한다.

  return { present: true, method, pathPart, isWrite, zone, kind };
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

  // 규칙 zone_policy(8단계): 경로 정보가 있는 요청에만 적용한다. 자료 구역을 경로 모양으로 나눠
  // 정해진 모양이 아니거나 다른 구역 접근·공지/강사 쓰기·메모 전체 목록이면 거부한다. role은 읽지 않는다.
  const z = classify(request);
  if (z.present) {
    // (1) 정해진 경로 모양이 아니면 거부(공지·강사도 "모르는 경로"가 아니라 분류 뒤 명시적으로 거부).
    if (z.zone === null) {
      return response(request, 'deny', 'zone_unknown_route', ['zone_policy']);
    }
    // (2) 메모 구역: ID 없는 전체 목록(/notes)은 여러 사람 자료를 여는 경로로 보고 거부한다.
    //     내 목록은 /my/notes만 허용한다. 내 단건(/notes/:id, /my/notes/:id)은 허용한다.
    //     소유자 비교는 자료 API가 담당한다.
    if (z.zone === 'memo') {
      if (z.kind === 'list' && z.pathPart === '/notes') {
        return response(request, 'deny', 'memo_list_forbidden', ['zone_policy']);
      }
      // 그 밖(내 목록 /my/notes, 단건)은 아래 6·7단계 규칙으로 이어진다.
    }
    // (3) 반 공지: 읽기(GET)만 허용, 쓰기(POST/PUT/PATCH/DELETE)는 누구에게나 거부.
    else if (z.zone === 'notice') {
      if (z.isWrite) {
        return response(request, 'deny', 'notice_write_forbidden', ['zone_policy']);
      }
    }
    // (4) 강사 자료: 판정기에서 모두 거부(읽기·쓰기 불문).
    else if (z.zone === 'instructor') {
      return response(request, 'deny', 'instructor_zone_forbidden', ['zone_policy']);
    }
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

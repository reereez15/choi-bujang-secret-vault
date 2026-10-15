// 9단계 탐지기: 같은 사용자(identity.sub)의 GET 조회가 어느 10분 구간에서든 120건을 넘으면
// 그 사용자에 대한 회수 제안(propose_revocation)을 낸다. 그 밖에는 관찰(observe)만 한다.
// 계약(docs/DETECT_EVENTS.md)의 at·method·identity.sub만 읽는다.
// 브라우저가 보낸 사용자 번호는 신원으로 쓰지 않는다(엔진이 검증한 사건만 전달된다는 전제).

const WINDOW_MS = 10 * 60 * 1000; // 10분
const THRESHOLD = 120;            // 이 수를 "넘을 때만"(즉 121건 이상) 회수 제안. 정확히 120은 제외.

// === 카드 1: 입력 정리 ===
// 가명 사용자(sub)·기기·요청 종류(method)·판정에 필요한 시각(at)만 읽는다.
// 메모 내용·토큰·설명은 저장하거나 출력하지 않는다. 형식이 맞지 않는 사건은 버린다.
function readEvent(e) {
  if (!e || typeof e !== 'object') return null;
  const sub = typeof e.identity?.sub === 'string' ? e.identity.sub : null;
  const method = typeof e.method === 'string' ? e.method.toUpperCase() : null;
  const t = typeof e.at === 'string' ? Date.parse(e.at) : NaN;
  if (sub === null || method === null || Number.isNaN(t)) return null;
  return { sub, method, t };
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  // 카드 1: 유효한 GET 사건만 사용자별로 모은다(다른 사용자끼리 합산하지 않는다).
  const bySub = new Map();
  for (const raw of events) {
    const ev = readEvent(raw);
    if (!ev || ev.method !== 'GET') continue; // GET만 센다
    if (!bySub.has(ev.sub)) bySub.set(ev.sub, []);
    bySub.get(ev.sub).push(ev.t);
  }

  // 카드 2: 각 사용자의 GET 시각을 정렬해, 어느 10분 구간에서든 120건을 넘는지 본다.
  // 슬라이딩 윈도우(투 포인터): 끝 사건에서 10분 이내로 들어오는 사건 수가 THRESHOLD를 넘으면 폭주.
  for (const [sub, times] of bySub) {
    times.sort((a, b) => a - b);
    let start = 0;
    for (let end = 0; end < times.length; end += 1) {
      // 윈도우를 [times[end]-10분, times[end]]로 유지한다(경계 포함).
      while (times[end] - times[start] > WINDOW_MS) start += 1;
      const countInWindow = end - start + 1;
      if (countInWindow > THRESHOLD) {
        // 카드 3: 회수 제안. 대상은 확인된 사용자(sub) 한 개로 한정하고 이유 코드를 함께 남긴다.
        return { action: 'propose_revocation', reasonCode: 'burst_read', subject: sub };
      }
    }
  }

  return { action: 'observe' };
}

import { randomUUID } from 'node:crypto';
import { createClient as createSupabaseClient } from '@supabase/supabase-js';
import { createNotesStore, NotesStoreError } from './notes-store.mjs';
import { createLoginVerifier } from './verify-login.mjs';

// 가상 메모 API. SUPABASE_URL과 서버 전용 SUPABASE_SECRET_KEY는 서버 환경변수에서만 읽는다.
// 키·토큰은 응답·로그·오류 문구 어디에도 넣지 않는다. 로그에는 고정 문구와 짧은 오류 코드만 남긴다.
//
// 모든 요청은 자료에 닿기 전에 Authorization 토큰을 틀의 src/verify-login.mjs로 검사한다.
// 브라우저가 보낸 userId·owner_id·role·쿼리 값은 신원으로 쓰지 않고, 검사 결과의 userId만 쓴다.
//
// 소유자 검사: 한 건 GET·PUT·DELETE는 DB의 owner_id가 검증된 사용자 ID와 같을 때만 처리한다.
// 남의 메모는 없는 메모와 똑같이 404로 답해서 id가 존재하는지도 알려 주지 않는다.
// 수정은 기존 행의 소유자가 본인인지 확인하고, 새 값에는 owner_id를 쓰지 않아 소유자가 바뀌지 않는다.
// 본문에 다른 사람의 owner_id를 담아 보내면 소유자 변경 시도로 보고 403으로 거부한다.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TITLE_MAX = 120;
const BODY_MAX = 2000;

function parseBody(req) {
  let value = req.body;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

// title·body만 읽는다. owner_id·userId·role 같은 다른 값은 무시한다.
function readNote(input) {
  if (typeof input.title !== 'string' || !input.title.trim() || input.title.trim().length > TITLE_MAX) {
    return { error: { error: 'invalid_input', field: 'title' } };
  }
  if (typeof input.body !== 'string' || input.body.length > BODY_MAX) {
    return { error: { error: 'invalid_input', field: 'body' } };
  }
  return { title: input.title.trim(), body: input.body };
}

export function createNotesApi({
  env = process.env,
  createClient = createSupabaseClient,
  createStore = createNotesStore,
  log = console.error,
  loadConfig = () => { throw new TypeError('missing_config_loader'); },
  createVerifier = createLoginVerifier,
  newId = randomUUID,
} = {}) {
  let verifier;
  const getVerifier = () => {
    verifier ??= createVerifier({ config: loadConfig(), supabaseSecretKey: env.SUPABASE_SECRET_KEY });
    return verifier;
  };
  let store;
  const getStore = () => {
    if (!store) {
      const url = env.SUPABASE_URL;
      const key = env.SUPABASE_SECRET_KEY;
      if (!url || !key) throw new TypeError('server_not_configured');
      store = createStore(createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } }));
    }
    return store;
  };

  const guarded = (allowed, run) => async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Vary', 'Authorization');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (!allowed.includes(req.method)) {
      res.setHeader('Allow', allowed.join(', '));
      return res.status(405).json({ error: 'method_not_allowed' });
    }
    let verify;
    try {
      verify = getVerifier();
    } catch {
      log('notes: 로그인 검사 설정이 없어 자료를 주지 않습니다.');
      return res.status(500).json({ error: 'login_not_configured' });
    }
    let identity = null;
    try {
      identity = await verify(req.headers?.authorization);
    } catch {
      identity = null;
    }
    if (!identity || typeof identity.userId !== 'string' || !identity.userId) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return res.status(401).json({ error: 'unauthorized' });
    }
    let notes;
    try {
      notes = getStore();
    } catch {
      log('notes: 서버 환경변수가 설정되지 않았습니다.');
      return res.status(500).json({ error: 'server_not_configured' });
    }
    try {
      return await run({ req, res, notes, userId: identity.userId });
    } catch (error) {
      if (error instanceof NotesStoreError) {
        log(`notes: 자료 처리에 실패했습니다 (${error.code}).`);
        return res.status(502).json({ error: 'upstream_error' });
      }
      log('notes: 자료 처리 중 예외가 발생했습니다.');
      return res.status(500).json({ error: 'server_error' });
    }
  };

  // /api/notes : GET 목록, POST 추가
  const collection = guarded(['GET', 'POST'], async ({ req, res, notes, userId }) => {
    if (req.method === 'GET') return res.status(200).json(await notes.list(userId));
    const input = parseBody(req);
    if (!input) return res.status(400).json({ error: 'invalid_input', field: 'body' });
    const note = readNote(input);
    if (note.error) return res.status(400).json(note.error);
    let id = newId();
    if (input.id !== undefined && input.id !== null) {
      if (typeof input.id !== 'string' || !UUID.test(input.id)) return res.status(400).json({ error: 'invalid_id' });
      id = input.id.toLowerCase();
    }
    try {
      await notes.create({ id, ownerId: userId, title: note.title, body: note.body });
    } catch (error) {
      if (error instanceof NotesStoreError && error.code === '23505') return res.status(409).json({ error: 'id_exists' });
      throw error;
    }
    return res.status(201).json({ id });
  });

  // /api/notes/:id : GET 한 건, PUT 수정, DELETE 삭제. 모두 본인 메모만 처리한다.
  const item = guarded(['GET', 'PUT', 'DELETE'], async ({ req, res, notes, userId }) => {
    const rawId = req.query?.id;
    if (typeof rawId !== 'string' || !UUID.test(rawId)) return res.status(400).json({ error: 'invalid_id' });
    const id = rawId.toLowerCase();
    const me = userId.toLowerCase();
    const notFound = () => res.status(404).json({ error: 'not_found' });
    const isMine = (row) => Boolean(row) && typeof row.ownerId === 'string' && row.ownerId.toLowerCase() === me;

    if (req.method === 'GET') {
      const found = await notes.get(id);
      return isMine(found) ? res.status(200).json({ id: found.id, title: found.title, body: found.body }) : notFound();
    }
    if (req.method === 'PUT') {
      const input = parseBody(req);
      if (!input) return res.status(400).json({ error: 'invalid_input', field: 'body' });
      // 소유자를 바꾸려는 시도(내가 아닌 owner_id)는 요청 전체를 거부한다. 내 ID와 같으면 바뀌는 것이 없어 무시한다.
      for (const claimed of [input.owner_id, input.ownerId]) {
        if (claimed !== undefined && claimed !== null && String(claimed).toLowerCase() !== me) {
          return res.status(403).json({ error: 'owner_change_forbidden' });
        }
      }
      if (input.id !== undefined && input.id !== null && String(input.id).toLowerCase() !== id) {
        return res.status(400).json({ error: 'id_mismatch' });
      }
      const note = readNote(input);
      if (note.error) return res.status(400).json(note.error);
      if (!isMine(await notes.get(id))) return notFound();
      return (await notes.update(id, userId, note)) ? res.status(200).json({ id }) : notFound();
    }
    if (!isMine(await notes.get(id))) return notFound();
    return (await notes.remove(id, userId)) ? res.status(200).json({ id }) : notFound();
  });

  return { collection, item };
}

// 이전 단계와 같은 이름으로 목록·추가 처리기를 돌려준다.
export const createNotesHandler = (options) => createNotesApi(options).collection;

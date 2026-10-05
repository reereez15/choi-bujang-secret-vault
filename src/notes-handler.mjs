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
// 알려진 약점(4단계에서 고칠 예정): 메모 한 건 GET·PUT·DELETE는 아직 소유자를 검사하지 않는다.
// 로그인한 사람이면 id만 알아도 다른 사람의 메모를 읽고 고치고 지울 수 있다.
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

  // /api/notes/:id : GET 한 건, PUT 수정, DELETE 삭제
  const item = guarded(['GET', 'PUT', 'DELETE'], async ({ req, res, notes }) => {
    const rawId = req.query?.id;
    if (typeof rawId !== 'string' || !UUID.test(rawId)) return res.status(400).json({ error: 'invalid_id' });
    const id = rawId.toLowerCase();
    if (req.method === 'GET') {
      const found = await notes.get(id);
      return found ? res.status(200).json(found) : res.status(404).json({ error: 'not_found' });
    }
    if (req.method === 'PUT') {
      const input = parseBody(req);
      if (!input) return res.status(400).json({ error: 'invalid_input', field: 'body' });
      if (input.id !== undefined && input.id !== null && String(input.id).toLowerCase() !== id) {
        return res.status(400).json({ error: 'id_mismatch' });
      }
      const note = readNote(input);
      if (note.error) return res.status(400).json(note.error);
      return (await notes.update(id, note))
        ? res.status(200).json({ id }) : res.status(404).json({ error: 'not_found' });
    }
    return (await notes.remove(id))
      ? res.status(200).json({ id }) : res.status(404).json({ error: 'not_found' });
  });

  return { collection, item };
}

// 이전 단계와 같은 이름으로 목록·추가 처리기를 돌려준다.
export const createNotesHandler = (options) => createNotesApi(options).collection;

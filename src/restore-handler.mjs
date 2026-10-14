// 10단계 제작 3: 비공개 가상 메모 사본(memo-backup.json)에서 지정한 ID 한 건만 복원한다.
// POST /api/restore/note { id }
//  - 로그인한 사용자만 호출할 수 있고, 복원 대상의 소유자가 그 사용자일 때만 복원한다.
//  - 사본의 ID·소유자·내용 해시를 대조해 무결성이 맞을 때만 되살린다.
//  - 다른 메모와 감사 기록은 건드리지 않는다(지정한 한 건만 복원).
// 본문·헤더의 owner_id·role은 신뢰하지 않는다. 소유자는 서버가 확인한 로그인 사용자다.
import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import { createClient as createSupabaseClient } from '@supabase/supabase-js';
import { createNotesStore } from './notes-store.mjs';
import { createLoginVerifier } from './verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

function parseBody(req) {
  let value = req.body;
  if (typeof value === 'string') { try { value = JSON.parse(value); } catch { return null; } }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

// 사본의 한 메모가 스스로 무결한지(저장된 해시가 내용과 맞는지) 확인한다.
function backupVerified(note) {
  if (!note || typeof note !== 'object') return false;
  const canon = JSON.stringify({ id: note.id, ownerSubject: note.ownerSubject, title: note.title });
  return note.sha256 === createHash('sha256').update(canon).digest('hex');
}

export function createRestoreApi({
  env = process.env,
  createClient = createSupabaseClient,
  createStore = createNotesStore,
  createVerifier = createLoginVerifier,
  loadConfig = () => { throw new TypeError('missing_config_loader'); },
  loadBackup,
  log = console.error,
  newId = randomUUID,
} = {}) {
  let verifier;
  const getVerifier = () => (verifier ??= createVerifier({ config: loadConfig(), supabaseSecretKey: env.SUPABASE_SECRET_KEY }));
  let store;
  const getStore = () => {
    if (!store) {
      const url = env.SUPABASE_URL, key = env.SUPABASE_SECRET_KEY;
      if (!url || !key) throw new TypeError('server_not_configured');
      store = createStore(createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } }));
    }
    return store;
  };

  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return res.status(405).json({ error: 'method_not_allowed' });
    }
    try {
      // 1) 로그인 확인
      let identity;
      try { identity = await getVerifier().verify(req.headers?.authorization); }
      catch { identity = null; }
      if (!identity || typeof identity.userId !== 'string' || !identity.userId) {
        return res.status(401).json({ error: 'unauthorized' });
      }

      // 2) 입력에서 복원 대상 ID만 읽는다(owner_id·role은 읽지 않는다).
      const input = parseBody(req);
      const id = typeof input?.id === 'string' ? input.id.toLowerCase() : null;
      if (!id || !UUID.test(id)) return res.status(400).json({ error: 'invalid_id' });

      // 3) 비공개 사본에서 그 ID의 메모를 찾는다. 없거나 검증 실패면 중단한다.
      const backup = typeof loadBackup === 'function' ? loadBackup() : null;
      const copy = Array.isArray(backup?.notes) ? backup.notes.find((n) => n.id?.toLowerCase() === id) : null;
      if (!copy) return res.status(404).json({ error: 'backup_not_found' });
      if (!backupVerified(copy)) return res.status(409).json({ error: 'backup_integrity_failed' });

      // 4) 소유자 대조: 복원 대상의 소유자가 로그인 사용자일 때만 복원한다.
      //    사본의 ownerSubject를 서버가 확인한 사용자 번호와 잇는 표(env)로 대조한다. 없으면 미설정으로 거부.
      const ownerId = resolveOwner(env, copy.ownerSubject);
      if (!ownerId) return res.status(403).json({ error: 'owner_binding_missing' });
      if (ownerId.toLowerCase() !== identity.userId.toLowerCase()) {
        return res.status(403).json({ error: 'not_owner' });
      }

      // 5) 그 한 건만 복원한다. 이미 있으면 보존(덮어쓰지 않음), 없으면 되살린다.
      const notes = getStore();
      const existing = await notes.get(id);
      if (existing) {
        // 다른 메모·감사 기록 보존. 이미 있는 건 변경하지 않는다.
        return res.status(200).json({ id, restored: false, reason: 'already_present' });
      }
      await notes.create({ id, ownerId, title: copy.title, body: '' });
      return res.status(201).json({ id, restored: true });
    } catch (error) {
      if (error instanceof TypeError && error.message === 'server_not_configured') {
        return res.status(500).json({ error: 'server_not_configured' });
      }
      log('restore: 복원 중 예외가 발생했습니다.');
      return res.status(500).json({ error: 'server_error' });
    }
  };
}

// 사본의 가명 소유자(ownerSubject)를 서버가 확인한 실제 사용자 번호로 잇는다.
// 서버 전용 환경변수 RESTORE_OWNER_<SUBJECT> 로 설정한다(없으면 복원 거부).
function resolveOwner(env, subject) {
  if (typeof subject !== 'string' || subject === '') return null;
  const key = 'RESTORE_OWNER_' + subject.replace(/[^A-Za-z0-9]/g, '_').toUpperCase();
  const value = env[key];
  return typeof value === 'string' && value ? value : null;
}

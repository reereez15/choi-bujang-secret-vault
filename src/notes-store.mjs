// 가상 메모를 학습 DB(vault_notes)에서 읽고 쓰는 얇은 층. 화면·API의 body는 DB의 content 칸에 저장한다.
// 서버 전용 키로 만든 클라이언트만 받는다. 오류에는 짧은 오류 코드만 담고 메시지·키·입력은 담지 않는다.
const TABLE = 'vault_notes';
const SAFE_CODE = /^[A-Za-z0-9_]{1,12}$/u;

export class NotesStoreError extends Error {
  constructor(error) {
    super('notes_store_error');
    this.name = 'NotesStoreError';
    this.code = SAFE_CODE.test(String(error?.code ?? '')) ? error.code : 'unknown';
  }
}

const toNote = (row) => ({ id: row.id, title: row.title, body: row.content });
const check = ({ error }) => { if (error) throw new NotesStoreError(error); };

export function createNotesStore(client) {
  return {
    // 로그인 사용자 본인이 만든 메모만 돌려준다.
    async list(ownerId) {
      const result = await client.from(TABLE).select('id, title, content')
        .eq('owner_id', ownerId)
        .order('created_at', { ascending: true }).order('id', { ascending: true });
      check(result);
      if (!Array.isArray(result.data)) throw new NotesStoreError(null);
      return result.data.map(toNote);
    },
    // 소유자 비교는 호출한 쪽이 한다. 그래서 owner_id까지 함께 돌려준다(응답으로 내보내지는 않는다).
    async get(id) {
      const result = await client.from(TABLE).select('id, title, content, owner_id').eq('id', id).maybeSingle();
      check(result);
      return result.data ? { ...toNote(result.data), ownerId: result.data.owner_id } : null;
    },
    // 서버가 확인한 사용자 번호를 owner_id로 저장한다.
    async create({ id, ownerId, title, body }) {
      const result = await client.from(TABLE)
        .insert({ id, owner_id: ownerId, title, content: body }).select('id').single();
      check(result);
      return result.data.id;
    },
    // 수정은 title·content만 쓰고 owner_id는 건드리지 않는다. 기존 행의 소유자가 본인일 때만 바뀐다.
    async update(id, ownerId, { title, body }) {
      const result = await client.from(TABLE).update({ title, content: body })
        .eq('id', id).eq('owner_id', ownerId).select('id');
      check(result);
      return Array.isArray(result.data) && result.data.length > 0;
    },
    // 삭제도 소유자가 본인인 행만 지운다.
    async remove(id, ownerId) {
      const result = await client.from(TABLE).delete().eq('id', id).eq('owner_id', ownerId).select('id');
      check(result);
      return Array.isArray(result.data) && result.data.length > 0;
    },
  };
}

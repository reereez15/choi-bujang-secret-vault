import { createClient as createSupabaseClient } from '@supabase/supabase-js';

// 서버 함수 본체. SUPABASE_URL과 서버 전용 SUPABASE_SECRET_KEY는 서버 환경변수에서만 읽는다.
// 키 값은 응답·로그·오류 문구 어디에도 넣지 않는다. 로그에는 고정 문구와 짧은 오류 코드만 남긴다.
const SAFE_CODE = /^[A-Za-z0-9_]{1,12}$/u;

export function createNotesHandler({
  env = process.env,
  createClient = createSupabaseClient,
  log = console.error,
} = {}) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return res.status(405).json({ error: 'method_not_allowed' });
    }
    const url = env.SUPABASE_URL;
    const key = env.SUPABASE_SECRET_KEY;
    if (!url || !key) {
      log('notes: 서버 환경변수가 설정되지 않았습니다.');
      return res.status(500).json({ error: 'server_not_configured' });
    }
    try {
      const client = createClient(url, key, {
        auth: { persistSession: false, autoRefreshToken: false },
      });
      const { data, error } = await client.from('vault_notes')
        .select('title, content')
        .order('created_at', { ascending: true })
        .order('title', { ascending: true });
      if (error || !Array.isArray(data)) {
        const code = SAFE_CODE.test(String(error?.code ?? '')) ? error.code : 'unknown';
        log(`notes: 자료 조회에 실패했습니다 (${code}).`);
        return res.status(502).json({ error: 'upstream_error' });
      }
      return res.status(200).json({
        notes: data.map(({ title, content }) => ({ title, content })),
      });
    } catch {
      log('notes: 자료 조회 중 예외가 발생했습니다.');
      return res.status(500).json({ error: 'server_error' });
    }
  };
}

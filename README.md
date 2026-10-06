# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 시작 틀에 들어 있던 메모 네 건은 가상 자료이며 2단계에서 DB로 옮겼습니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 현재 상태: 5단계 「자료 요청을 서버 한곳으로 모읍니다」

**지금 작동하는 기능**
- 자료 요청은 **화면 → 서버 함수(`/api/notes`) → DB** 한 길로만 갑니다. 로그인도 같은 서버를 거칩니다. **브라우저 코드(`public/`)에는 Supabase 키도, Supabase SDK도, 프로젝트 주소도 없고**(시험이 이 상태를 고정합니다), 화면의 요청은 모두 같은 서버의 `/api/notes*`와 `/api/auth/*`입니다.
- 로그인 화면(`public/index.html`, `public/auth.js`)은 이메일·비밀번호를 서버 함수 `POST /api/auth/login`에 보냅니다. 서버가 Supabase Auth에 대신 로그인하고(공식 SDK는 서버에서만 씁니다) 세션(`access_token`, `refresh_token`, `expires_at`, 사용자 id·이메일)만 돌려줍니다. 화면은 그 세션을 **이 탭의 sessionStorage**에만 두고(탭을 닫으면 사라지고 새로고침하면 유지됩니다), 만료 1분 전에 `POST /api/auth/refresh`로 갱신하며, 로그아웃하면 저장된 세션을 지우고 `POST /api/auth/logout`으로 서버의 세션도 끝냅니다. 비밀번호는 서버로 보내기만 하고 저장하지 않으며 응답·로그에 되돌려 쓰지 않습니다. 로그인 실패 이유(이메일·비밀번호 불일치, 인증 미완료, 요청 과다, 서버 연결 실패 등)는 화면에 보입니다.
- 자료 API(Vercel 서버 함수 `api/notes.js`, `api/notes/[id].js`, 본체 `src/notes-handler.mjs`와 `src/notes-store.mjs`):
  - `GET /api/notes`는 로그인 사용자 **본인** 메모의 배열 `[{id,title,body}]`, `POST /api/notes`는 `{id?,title,body}`를 받아 `{id}`를 돌려줍니다.
  - `GET·PUT·DELETE /api/notes/:id`는 한 건 조회 `{id,title,body}`, 수정 `{title,body}`, 삭제입니다. 지운 뒤 GET은 404입니다.
  - 모든 요청은 DB에 닿기 전에 틀의 `src/verify-login.mjs`로 `Authorization` 토큰을 검사합니다. 토큰이 없거나 검사에 실패하면 자료 없이 401입니다.
  - 소유자 검사: 한 건 요청은 DB의 `owner_id`가 검증된 사용자 ID와 같을 때만 처리하고, 남의 메모는 없는 메모와 같은 404입니다. 수정 본문에 내 ID가 아닌 `owner_id`가 있으면 403으로 거부합니다. 추가할 때 `owner_id`는 검증된 ID로만 저장합니다.
- **DB 직접 접근 차단:** 테이블 `vault_notes`에서 `PUBLIC`·`anon`·`authenticated`의 직접 권한(열 단위 포함)을 모두 회수했습니다. 서버 함수가 쓰는 서버 전용 키의 역할 `service_role`만 읽기·추가·수정·삭제 권한을 갖습니다. RLS는 켜져 있고 정책 네 개(`auth.uid() = owner_id`)도 그대로 두었지만, 권한이 없어서 지금은 쓰이지 않고 나중에 실수로 권한이 열려도 한 번 더 막는 장치입니다. 테이블과 권한을 만든 SQL 파일은 가상 메모 문장이 들어 있어 이 저장소에 두지 않았습니다.
- **원본 자료 API 주소:** `aleph.config.json`의 `originalApiUrl`은 Supabase Data API의 메모 테이블 주소(`…/rest/v1/vault_notes`)이고 쿼리·해시·인증 정보가 없습니다. 이 주소를 공개용(anon) 키나 로그인 토큰으로 직접 부르면 `401`/`403`과 `permission denied`(코드 42501)로 거부됩니다. 배포할 때 빌드가 만드는 `/aleph.json`(배포 식별 파일)에도 5단계부터 같은 `originalApiUrl`이, 3단계부터 `allowedRoutes`(허용 경로 여덟 개)가 들어가고, 값이 없거나 모양이 틀리면 빌드가 멈춥니다. 심판은 배포된 `/aleph.json`에서 이 값들을 읽습니다.
- `aleph.config.json`은 `step` 5이고, `identityProvider`(발급자·공개키 주소·audience, 공개 값만)와 `allowedRoutes`(`GET /api/notes`, `POST /api/notes`, `GET /api/notes/:id`, `PUT /api/notes/:id`, `DELETE /api/notes/:id`, `POST /api/auth/login`, `POST /api/auth/refresh`, `POST /api/auth/logout`), `originalApiUrl`을 구현과 맞춰 적었습니다.
- 서버 함수는 `SUPABASE_URL`, 로그인에 쓰는 공개용(publishable) 키 `SUPABASE_PUBLISHABLE_KEY`, 서버 전용 `SUPABASE_SECRET_KEY`를 **Vercel 환경변수**에서만 읽습니다. 세 값은 Vercel 프로젝트 Settings → Environment Variables 입력란에 직접 넣고(키는 Sensitive로), 코드·Git·채팅·로그·브라우저 파일에는 쓰지 않습니다. `SUPABASE_PUBLISHABLE_KEY`가 없으면 로그인이 `server_not_configured`로 실패하고 화면에 "로그인 서버 설정이 아직 없습니다"가 보입니다.
- `data.json`과 `public/data.json`은 `{ "notes": [] }`입니다. 배포된 `/data.json`에는 메모가 없습니다.
- 첫 화면을 포함한 모든 응답에 `vercel.json`의 `headers`로 `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`를 붙입니다. 서버 함수 응답에는 코드가 `nosniff`를 따로 붙입니다. 화면의 인라인 스크립트와 스타일 때문에 `Content-Security-Policy`는 아직 쓰지 않습니다.

**다시 실행하는 방법**
- 로컬 시험: `npm ci` 다음 `npm run test:r5`. 가짜 로그인과 가짜 DB로 하는 연습이며 실제 DB 연결이나 배포를 증명하지 않습니다. (Windows PowerShell에서 `npm`이 막히면 `npm.cmd`를 씁니다.)
- 배포 전 한 번: Vercel 환경변수에 `SUPABASE_PUBLISHABLE_KEY`(Supabase 대시보드의 Publishable key)를 넣고 다시 배포합니다. 값은 저장소·채팅에 쓰지 않습니다.
- 배포 확인: 시크릿 창에서 `짧은주소/aleph.json`을 열어 `commit`이 방금 푸시한 커밋이고 `allowedRoutes`와 `originalApiUrl`(`https://…/rest/v1/vault_notes`)이 들어 있는지 보고, 첫 화면의 응답 헤더에 `x-content-type-options: nosniff`가 있는지 보고, A로 로그인해 메모를 추가·수정·삭제하고, B로 로그인하면 B의 메모만 보이는지, 로그인 없이 `/api/notes`를 열면 `unauthorized`인지 봅니다.
- DB 권한 확인(Supabase SQL Editor, 하나씩 실행): `information_schema.role_table_grants`에서 `vault_notes`의 `PUBLIC`·`anon`·`authenticated` 줄이 없는지, `has_table_privilege`와 `has_any_column_privilege`가 `anon`·`authenticated`에서 모두 `false`인지, `pg_policies`가 4개이고 RLS가 켜져 있는지 봅니다.
- 원본 직접 호출 확인(브라우저 Console): 브라우저 코드에는 키가 없으므로 Supabase 대시보드의 공개용 키를 Console에서만 잠깐 써서 `…/rest/v1/vault_notes`를 부릅니다. 로그인 없이는 `401`, 이 탭의 로그인 토큰(`sessionStorage`의 `vault.session`)을 붙여도 `403`과 `42501`이 나와야 합니다.
- 자기 점검: `npm run bundle`의 `src/attack-check.mjs`가 로그인 없는 요청, 위조 토큰, `/data.json`, 응답의 키 노출, 원본 자료 API 직접 요청(anon 키로 GET·POST·PATCH·DELETE)을 실제로 보내 결과만 기록합니다. 쓰기 점검은 저장되지 않는 빈 본문이나 없는 id만 써서 데이터를 바꾸지 않습니다. 원본 자료 API 점검에 쓸 공개용 키는 저장소에 없으므로 환경변수 `ATTACK_CHECK_ANON_KEY`로 받습니다. 로그인 사용자 요청과 상대 메모 접근·소유자 변경 점검은 환경변수 `ATTACK_CHECK_TOKEN`(A)과 `ATTACK_CHECK_TOKEN_B`(B)가 있을 때만 보내고, 토큰이 없거나 배포 서버에 닿지 못한 점검은 "미실행"으로 적습니다. 토큰 값은 어디에도 적지 않습니다. 심판의 판정이 아닙니다.

**알려진 약점 (아직 남아 있음)**
- 서버 함수가 자료로 가는 **유일한 통로이자 유일한 소유자 검사 지점**입니다. 서버 함수는 RLS를 건너뛰는 `service_role`로 접근하므로 DB의 소유자 정책은 이 경로에 적용되지 않습니다. 서버 코드의 소유자 검사에 오류가 생기면 DB가 대신 막아 주지 못합니다. 서버 전용 키가 새면 RLS와 상관없이 모든 메모를 읽을 수 있으므로, 키는 Vercel 환경변수에만 둡니다.
- 로그인 비밀번호가 우리 서버 함수를 지나갑니다. 서버는 비밀번호를 저장하거나 기록하지 않고 Supabase Auth로 넘기기만 하지만, 이 함수가 오작동하거나 공격받으면 영향을 받습니다. 로그인 시도 횟수 제한은 Supabase Auth의 제한에 맡기고, 이 함수에는 따로 두지 않았습니다.
- 메모를 다른 사용자와 공유하는 기능은 없습니다. 메모는 만든 사람 한 명만 다룹니다. 의도한 동작입니다.
- 이미 쓰인 id로 메모를 추가하면 409(`id_exists`)가 나옵니다. 남의 메모 id로 시도해도 같은 응답이라 "그 id가 존재한다"는 사실은 알 수 있습니다. 내용을 읽거나 덮어쓸 수는 없습니다.
- 원본 자료 API 주소(`…/rest/v1/vault_notes`) 자체는 인터넷에서 열려 있고, 요청은 권한 오류로 거부될 뿐입니다. 이 표의 이름과 위치가 공개 저장소에 적혀 있습니다.
- 로그인 세션(리프레시 토큰 포함)을 이 화면의 코드가 `sessionStorage`에 직접 보관합니다. 페이지에 악성 스크립트가 실행되면 읽힐 수 있어서, 이 화면은 서버에서 받은 글을 `textContent`로만 그리고 외부 스크립트를 쓰지 않으며, 탭을 닫으면 세션이 사라지게 했습니다.
- 지난 커밋과 옛 배포의 긴 주소(`…-해시-계정.vercel.app`)에는 1단계의 가상 메모가 남아 있습니다. 지금 파일을 바꿔도 이 이력은 지워지지 않습니다.

**5단계 확인 기록 (2026-10-06, 직접 확인한 것만 적었습니다)**
- 브라우저 코드에는 Supabase 직접 자료 호출(`.from(`, `.rpc(`, `/rest/v1`, storage, realtime)이 없음을 검색으로 확인했고, 이를 시험으로 고정했습니다.
- DB 권한을 회수하기 전에 A 계정으로 추가·수정·삭제가 되는 것을 배포 화면에서 확인했습니다. 회수 전후 `role_table_grants`, `has_table_privilege`, `has_any_column_privilege`, 원본 ACL, RLS·정책 수를 대조했습니다. 회수 전에는 `authenticated`에 `SELECT`·`INSERT`·`UPDATE`·`DELETE`가 있었고, 회수 후에는 `PUBLIC`·`anon`·`authenticated` 권한이 모두 없고 `service_role`과 RLS(켜짐)·정책 4개는 그대로였습니다.
- 회수 뒤에도 배포 화면에서 A의 추가·수정·삭제가 이전과 똑같이 동작했습니다.
- 로그인한 브라우저 Console에서 원본 자료 API를 공개용 키로 직접 불러, 로그인 없이는 `401`, 로그인 토큰을 붙여도 `403`이고 둘 다 `permission denied for table vault_notes`(코드 42501)였습니다. 4단계에서는 로그인하면 본인 행이 돌아왔습니다.
- 심판이 지적한 조건(`/aleph.json`의 `originalApiUrl`·`allowedRoutes`, 첫 화면의 보안 헤더)은 고친 뒤 배포된 `/aleph.json`과 응답 헤더로 확인했습니다.
- 화면 코드에서 공개 키를 없애고 로그인을 서버 함수로 옮긴 변경은 로컬 시험과 가짜 인증 서버로만 확인했고, 실제 배포에서의 로그인·새로고침·로그아웃은 이 README를 쓴 시점에 **미실행**입니다. `npm run bundle`의 점검 결과도 제출 묶음의 `attackAttempts`에 따로 적힙니다.

**4단계 당시 확인 기록 (2026-10-06)**
- 기존 가상 메모 네 건은 A 계정, 시험 메모 한 건은 B 계정의 `owner_id`로 연결했고 소유자가 없는 행은 0건입니다.
- B로 로그인해 A의 "과제" 메모 id로 GET·PUT·DELETE를 보냈을 때 모두 `404`였고 A의 메모는 그대로였습니다. 화면에서 A는 네 건, B는 한 건만 보였습니다.
- 소유자 변경(403) 거부는 `attack-check`가 배포에서 확인했습니다(두 사용자 토큰을 넘겨 실행한 결과).

## 가상 메모 노출 확인 절차 (2단계)

현재 배포 파일과 GitHub 최신 파일에 가상 메모 문장이 남아 있는지 검색하는 절차입니다. 검색어를 이 README나 코드에 적으면 검색 결과에 걸리므로, 검색어는 저장소에 쓰지 않고 확인할 때마다 DB에서 가져옵니다.

1. **검색어 준비:** Supabase SQL Editor에서 `select title, content from public.vault_notes;`를 실행해 메모 문장 하나와 그 안의 고유한 구절 하나를 고릅니다. 이 문장은 저장소, 커밋 메시지, 채팅에 붙이지 않습니다.
2. **GitHub 최신 파일 검색:** `git fetch` 후 `git grep -c "구절" origin/main`을 실행합니다. 출력이 없으면 0건입니다. 웹의 코드 검색은 색인이 늦을 수 있어서 `git grep` 결과를 기준으로 합니다. 설정 파일의 확인 표시(`sampleMarker`)는 메모 문장이 아니라서 검색 대상이 아닙니다.
3. **현재 배포 파일 검색:** 시크릿 창에서 짧은 주소(Domains의 `…vercel.app`)로 아래를 엽니다. 모두 구절이 없어야 합니다.
   - `/data.json`: `{ "notes": [] }`만 보여야 합니다.
   - `/` 페이지 소스(Ctrl+U): 화면에는 카드가 그려지지만 소스에는 메모 문장이 없어야 합니다.
   - `/aleph.json`: 배포 식별 정보만 있어야 합니다.
4. **공개 API 확인:** 로그아웃한 시크릿 창에서 `/api/notes`를 엽니다. 파일이 아니라 서버 함수의 응답이라 3번에 넣지 않고 따로 기록합니다. 3단계부터는 로그인 없이 열면 `unauthorized`로 거부돼야 하고, 메모가 보이면 문제입니다.
5. **배포 이력 확인:** Vercel Deployments와 프로젝트 목록에 옛 배포나 같은 저장소에 연결된 중복 프로젝트가 남아 있는지 봅니다. 남아 있으면 그 주소도 3번과 같은 방법으로 열어 봅니다.

**2단계 당시 확인 기록 (2026-10-05, 실제로 실행한 것만 적었습니다)**

검색 결과
- GitHub 최신 파일(`origin/main`): 메모 문장 0건. `git grep`으로 확인했습니다.
- 옛 공개 커밋 `f459923`: `data.json`과 `public/data.json`에 메모 문장이 각각 4건 남아 있습니다. 이력이라 지금 파일을 바꿔도 지워지지 않습니다.
- 배포 `/` 페이지 소스: 메모 문장이 없고, 화면은 `/api/notes`를 불러 그립니다. 확인했습니다.
- 배포 `/aleph.json`: 2단계, 저장소 주소, 확인 시점의 최신 커밋이 기록돼 있습니다. 확인했습니다.
- 배포 `/data.json`: 2단계 재배포 뒤 확인했고, 빈 목록(`{ "notes": [] }`)만 보였습니다. 메모 문장은 없었습니다.

남은 약점
- 공개 API(2단계 당시): `/api/notes`를 로그인이나 키 없이 열었을 때 가상 메모 네 건이 응답되는 것을 직접 확인했습니다. 응답 본문에 키로 보이는 값은 없었습니다. 3단계에서 로그인 확인으로 막았습니다.
- 과거 노출: 옛 공개 커밋과 옛 배포 주소에 1단계의 가상 메모가 남아 있는 동안에는 과거 노출이 해소됐다고 보지 않습니다. 이 검색은 지금 파일 상태만 확인할 뿐 이전에 공개됐던 사실을 되돌리지 못합니다.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

1단계 당시에는 배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있었고, `/data.json`에 같은 가상 메모가 공개됐습니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포하고, `api/` 폴더의 서버 함수는 Vercel이 함께 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 1단계에서는 자리표시자였고 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성하며, 지금은 실제 저장소와 배포 주소가 들어 있습니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 단계별 요청을 보내 결과만 기록합니다. 1단계에서는 `/data.json`의 공개 가상 메모 확인 표시를 읽었고, 지금은 위 "자기 점검"에 적은 요청을 보냅니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 했고, 2단계에서 바꿨습니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

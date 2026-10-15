# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 시작 틀에 들어 있던 메모 네 건은 가상 자료이며 2단계에서 DB로 옮겼습니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 현재 상태: 11단계 「나만의 접속 앱을 완성합니다」

6단계까지의 자료 보호와 기기 등록 규칙은 그대로이고, 7단계에서 판정기 `src/decider.mjs`에 평소와 다른 접속을 다시 확인하는 규칙 `step_up_required`를 더했습니다(아래 "7단계" 절).

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
- `aleph.config.json`은 `step` 11이고, `identityProvider`(발급자·공개키 주소·audience, 공개 값만)와 `allowedRoutes`(`GET /api/notes`, `POST /api/notes`, `GET /api/notes/:id`, `PUT /api/notes/:id`, `DELETE /api/notes/:id`, `POST /api/auth/login`, `POST /api/auth/refresh`, `POST /api/auth/logout`), `originalApiUrl`을 구현과 맞춰 적었습니다.
- 서버 함수는 `SUPABASE_URL`, 로그인에 쓰는 공개용(publishable) 키 `SUPABASE_PUBLISHABLE_KEY`, 서버 전용 `SUPABASE_SECRET_KEY`를 **Vercel 환경변수**에서만 읽습니다. 세 값은 Vercel 프로젝트 Settings → Environment Variables 입력란에 직접 넣고(키는 Sensitive로), 코드·Git·채팅·로그·브라우저 파일에는 쓰지 않습니다. `SUPABASE_PUBLISHABLE_KEY`가 없으면 로그인이 `server_not_configured`로 실패하고 화면에 "로그인 서버 설정이 아직 없습니다"가 보입니다.
- `data.json`과 `public/data.json`은 `{ "notes": [] }`입니다. 배포된 `/data.json`에는 메모가 없습니다.
- 첫 화면을 포함한 모든 응답에 `vercel.json`의 `headers`로 `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`를 붙입니다. 서버 함수 응답에는 코드가 `nosniff`를 따로 붙입니다. 화면의 인라인 스크립트와 스타일 때문에 `Content-Security-Policy`는 아직 쓰지 않습니다.

**다시 실행하는 방법**
- 판정기 연습: `npm run decider:test`. 등록 기기 요청은 통과(allow), 미등록 기기 가상 요청은 `deny`·`device_not_registered`여야 합니다. 심판 판정이 아닙니다.
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

## 11단계 「나만의 접속 앱을 완성합니다」

화면(`public/`)에 설치형 웹앱 설정과 기기 승인 화면을 붙였습니다. 서버의 보호 규칙은 그대로이고, 화면은 승인 상태를 **표시만** 합니다.

### 설치형 웹앱 (제작 1)
- `public/manifest.json`: 앱 이름(최부장의 비밀창고), 설명(로그인·기기 승인 안내와 오프라인에서는 자료가 보이지 않음), `display: standalone`, 테마색, 아이콘(`public/icon.svg`).
- `index.html`에 `manifest`·`theme-color`·아이콘을 연결했습니다. 접속 프로그램을 따로 만들거나 설치하지 않습니다.
- 설치됐다는 사실을 기기 확인이 끝난 것으로 쓰지 않습니다. 설치 여부와 승인 여부는 별개입니다.

### 기기 승인 화면 (제작 2)
- 로그인해도 바로 자료를 열지 않고 기기 승인 영역을 먼저 보여 줍니다. **승인 전에는 보호 자료(메모)를 요청하지도, 표시하지도 않습니다.** 메모 영역(작성 폼·목록)은 `#memo` 섹션 안에 두고, 승인 전에는 섹션을 숨기는 것에 더해 그 내용을 DOM에서 들어냅니다. 승인에 성공한 뒤에만 되돌리고 자료를 채웁니다(정적 화면에도 승인 전에는 자료 영역이 없습니다).
- "기기 승인 요청" 버튼은 승인 확인 전용 경로 `GET /api/device/check`를 호출합니다. 이 경로는 서버가 로그인을 검증한 뒤 **서버 판정기(`decide`)에 요청을 넘겨** 판정기가 `allow`를 낼 때만 `{ approved: true }`를 돌려줍니다. 승인은 화면·버튼이 아니라 서버 판정기가 결정하며, 판정기가 막으면(`deny`/`step_up`) 자료실을 열지 않습니다. 응답에 메모 등 보호 자료는 담지 않고, 승인이 성공한 **뒤에야** 화면이 메모를 불러옵니다.
- 승인은 화면이 스스로 정하지 않습니다. 설치됐다는 사실이나 승인 버튼 클릭만으로 권한을 주지 않고, 서버가 확인한 결과만 다음 화면을 엽니다. 세션이 바뀌면 승인을 처음부터 다시 받습니다.
- 서버가 거부하거나 연결이 안 되면(오프라인 등) 자료를 숨기고 안내만 보여 줍니다.

### 토큰을 브라우저에 두지 않음
- 로그인 토큰과 리프레시 토큰을 `localStorage`·`sessionStorage`·쿠키에 넣지 않습니다. 세션은 탭 메모리(변수)에만 둡니다. 새로고침하면 메모리가 비므로 다시 로그인합니다. 화면 코드·Git·제출물 어디에도 기기 키나 토큰 값을 남기지 않습니다.

6~10단계의 서버 규칙(판정기·탐지기·자료 API·백업/복원)은 그대로 유지됩니다. 새 화면에서도 기존 보호 요청의 정상·거부 결과는 서버가 결정합니다.

확인 순서 (로컬):

1. `npm run test:r5` — 전체 통과(화면 변경이 기존 보호 시험을 깨지 않는지).
2. 배포 후 화면(실측): 로그아웃 상태엔 자료 없음. 로그인 후 승인 전에는 메모를 요청하지 않음(네트워크 탭에 `/api/my/notes` 호출 없음). "기기 승인 요청" → `GET /api/device/check` 성공 시 메모 표시, 거부/오프라인이면 숨김 유지. 새로고침하면 로그아웃.
3. 설치(실측): 브라우저에서 앱 설치가 뜨는지(manifest 인식). 설치해도 승인 전에는 자료가 보이지 않는지.

**11단계 확인 기록 (2026-10-14, 직접 실행한 것만 적었습니다)**
- `test:r5` 전체 통과. manifest JSON 유효, 기기 승인 영역·버튼 핸들러 추가 확인.
- 승인 로직: 로그인 후 승인 전 메모 숨김, 승인 요청이 서버 응답으로만 열림(버튼·저장소로 권한 안 줌) 확인.
- 배포 서버에서의 설치·승인 실측: 미실행(배포 후 브라우저에서 확인).

## 10단계 「백업에서 자료실을 되살립니다」

침해 전 검증한 안전 정책과 가상 메모 사본으로 자료실을 되살립니다. 실제 운영 정책·DB는 건드리지 않고, 복원할 범위를 실행 전에 보여 줍니다.

### 안전 정책 백업/복원 (제작 1·2)
- 안전 정책 사본: `policy-backup.json` (검증된 `allowedRoutes` + 무결성 해시). 사본이 없거나 해시 검증이 실패하면 중단합니다.
- 차이 보기(실행 전): `npm run policy:diff` — 복원할 버전과 바뀔 범위(allowedRoutes의 추가·제거)를 보여 줍니다.
- 되돌리기: `npm run policy:restore -- --apply` — `aleph.config.json`의 `allowedRoutes`만 안전 정책으로 교체합니다. 주소·발급자·`step` 등 다른 설정과 감사 이력은 보존합니다. `git reset --hard`는 쓰지 않습니다.

### 가상 메모 한 건 복원 (제작 3)
- 서비스·경로: `POST /api/restore/note` (요청 본문 `{ "id": "<복원할 메모 ID>" }`)
- 비공개 가상 메모 사본: `memo-backup.json` (시험 계정 B의 메모, ID·소유자(가명)·제목·내용 해시).
- 동작: 로그인 사용자만 호출하고, 사본에서 지정한 ID 한 건을 찾아 **ID·소유자·내용 해시를 대조**한 뒤, 그 메모의 소유자가 로그인 사용자일 때만 복원합니다. 이미 있으면 보존(덮어쓰지 않음), 없으면 되살립니다. 다른 메모와 감사 기록은 건드리지 않습니다.
- 소유자 연결: 사본의 가명 소유자(`ownerSubject`)를 서버 전용 환경변수 `RESTORE_OWNER_<SUBJECT>`로 실제 사용자 번호와 잇습니다. 없으면 복원을 거부합니다. 본문·헤더의 `owner_id`·`role`은 신뢰하지 않습니다.
- 판정기도 `POST /api/restore/note`만 메모 구역으로 허용하고, 다른 메서드(GET·DELETE 등)는 거부합니다.

### 복구 뒤 재실행 순서 (제작 4)
복원이 끝나면 아래 순서로 1~9단계의 정상·금지 요청을 다시 확인합니다. 실행하지 않은 항목은 "미실행"으로 둡니다(결과를 꾸미지 않습니다).

1. 정책 복원 확인: `npm run policy:diff`가 "변경 없음"인지(안전 정책과 같아졌는지).
2. 로컬 규칙 시험: `npm run test:r5`(전체), `npm run decider:test`(6·7·8·복원 경로), `npm run detect:test`(9단계), `npm run fixture:7`(7단계).
3. 배포 후 자료 접근(실측): A 로그인 → 내 목록(`GET /api/my/notes`)·내 메모 조회 정상. B로 A 메모 조회·수정·삭제·목록 → 거부(404/목록 0건). (8단계)
4. 구역 금지(실측): 메모 전체 목록(`GET /api/notes`)·공지 쓰기·강사 경로 → 거부. (8단계)
5. 원본 API 직접 호출 → 401/403. (5단계)
6. 메모 한 건 복원(실측): `POST /api/restore/note`로 B 메모 복원 후, 복원된 메모의 ID·소유자·내용 해시가 사본과 같은지 확인. (10단계)

미실행(심판 환경에서 확인): 운영 엔진을 통한 정상 쓰기, 실제 강사 접속, 엔진이 검증한 사건 전달과 실제 회수 집행, 배포 서버에서의 위 실측 항목(토큰·키가 있을 때만 실행).

**10단계 확인 기록 (2026-10-14, 직접 실행한 것만 적었습니다)**
- `policy:diff`로 바뀔 범위 표시, 침해 시뮬 후 `policy:restore --apply`로 allowedRoutes만 복원되고 다른 설정 보존 확인. 사본 없음·해시 실패 시 중단 확인.
- 복원 API: B 소유자 복원 성공·ID/소유자/내용 해시 일치, 타인 복원 403, 비로그인 401, 없는 ID 404, GET 405 확인.
- `test:r5` 전체 통과, `decider:test`·`detect:test`·`fixture:7` 통과.
- 배포 서버에서의 실측(3~6)과 운영 엔진 경로: 미실행.

## 9단계 「도플갱어를 찾고 권한을 거둡니다」

탐지기 `src/detect.mjs`의 `detect(events)`를 구현했습니다. 계약(`docs/DETECT_EVENTS.md`)의 `at`·`method`·`identity.sub`만 읽고, 메모 내용·토큰·설명은 저장하거나 출력하지 않습니다.

- 입력 정리: 형식이 맞는 `GET` 사건만 사용자(`identity.sub`)별로 모읍니다. 깨진 사건은 버리고, 다른 사용자의 사건을 합산하지 않습니다.
- 탐지 규칙: 같은 사용자의 `GET` 조회가 어느 10분 구간에서든 **120건을 넘으면**(121건 이상) 폭주로 봅니다. 시각을 정렬해 10분 슬라이딩 윈도우(투 포인터)로 셉니다. 정확히 120건은 제외하고, 10분 밖으로 흩어진 사건은 같은 묶음으로 세지 않습니다.
- 회수 제안: 폭주가 확인되면 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject: 그 사용자 }`를 돌려줍니다. 대상은 확인된 사용자 한 명으로 한정하고 이유 코드를 함께 남깁니다. 그 밖에는 `{ action: 'observe' }`입니다.
- 6·7·8단계 규칙은 그대로 유지됩니다. 탐지기는 판정기와 별개 함수이며, 회수 API를 직접 만들거나 기기 권한을 임의로 바꾸지 않습니다.

확인 순서 (로컬 연습):

1. `npm ci` 뒤 `npm run detect:test` — 여섯 줄(정상 30건·120건 observe, 121건·200건 propose_revocation, 서로 다른 사용자·10분 밖 흩어짐 observe)이 모두 `통과`여야 합니다.
2. `npm run decider:test`와 `npm run test:r5`로 6·7·8단계가 유지되는지 확인합니다.

이 연습은 가상 사건으로 하며 심판 판정이 아닙니다. 운영 반 엔진이 검증한 사건 전달과 실제 회수 집행은 별도 경로이며, 실제 회수·시간은 심판이 확인합니다(미검증).

**9단계 확인 기록 (2026-10-14, 직접 실행한 것만 적었습니다)**
- 학생 PC에서 `detect:test` 여섯 줄 통과, `decider:test`·`test:r5` 전체 통과.
- 경계값(120 observe / 121 propose_revocation), GET만 집계, 사용자별 분리, 10분 윈도우 확인.
- 운영 엔진 사건 전달·실제 회수 집행: 미검증(심판 환경에서 확인).

## 8단계 「자료마다 갈 수 있는 구역을 나눕니다」

판정기 `src/decider.mjs`에 구역 규칙 `zone_policy`를 더했습니다. 계약의 `service`·`method`·`route`·`path`만 보고, 요청 본문의 `role`·`owner`는 읽지 않습니다. 경로 모양은 계약 예시대로 `GET /notes/:id` 형태이며 앞의 `/api`는 있어도 없어도 같게 봅니다.

- 구역 정의: 메모·반 공지·강사 자료를 경로 모양으로 나눕니다. 공지·강사도 "모르는 경로"로 두지 않고 명시적으로 분류한 뒤 정책을 적용합니다.
- 정해진 경로 모양이 아니면 거부합니다(`zone_unknown_route`). `:id` 자리에 `export` 같은 기능 경로가 오면 모양이 맞지 않아 거부됩니다.
- 반 공지는 읽기(GET)만 허용하고 쓰기(POST/PUT/PATCH/DELETE)는 누구에게나 거부합니다(`notice_write_forbidden`). 공지 수정은 서버의 관리 경로가 처리합니다.
- 강사 자료는 판정기에서 모두 거부합니다(`instructor_zone_forbidden`).
- 메모 전체 목록 경로(`/notes`, ID 없는 목록)는 여러 사람 자료를 여는 경로로 보고 거부합니다(`memo_list_forbidden`). 내 목록은 명시적 경로 `GET /api/my/notes`만 허용하고, 단건 조회·수정·삭제(`/notes/:id`)는 허용합니다. 내 목록 API는 기존 메모 핸들러를 재사용해 같은 서버 소유자 필터(본인 것만)를 유지합니다. 메모의 소유자 비교와 소유자 변경 거부(403)는 판정기가 아니라 자료 API가 합니다.
- 6단계 기기 등록과 7단계 재인증 규칙은 그대로 유지됩니다. `RULE_IDS`는 `['device_registered', 'step_up_required', 'zone_policy']`이고 모든 응답의 `ruleIds`는 이 안의 이름만 씁니다.
- `aleph.config.json`의 `allowedRoutes`에는 판정기가 허용하는 경로만 둡니다: 내 목록 `GET/POST /api/my/notes`, 단건 `GET/PUT/DELETE /api/notes/:id`, 로그인 경로. 메모 전체 목록·공지·강사 쓰기 경로는 넣지 않습니다. 화면도 목록·추가는 `/api/my/notes`를, 단건은 `/api/notes/:id`를 부릅니다.

확인 순서 (로컬 연습):

1. `npm ci` 뒤 `npm run decider:test` — 네 줄(등록 기기 허용, 미등록 거부, 복합 이상 step_up, 재확인 허용)이 모두 `통과`여야 합니다.
2. `npm run fixture:7` — 정상 `allow`, 복합 이상 `step_up`.
3. `npm run test:r5` — 전체 통과(`fail 0`).

구역 규칙은 가상 요청으로 확인하는 연습이며 심판 판정이 아닙니다. 메모 소유자 격리와 공지·강사 권한의 실제 자료 차단은 자료 API가 담당하며, 강사 공지 쓰기 API는 제공하지 않습니다(판정기에서 거부). 미검증 범위: 운영 엔진을 통한 정상 쓰기·실제 강사 접속.

**8단계 확인 기록 (2026-10-14, 직접 실행한 것만 적었습니다)**
- 학생 PC에서 `decider:test` 네 줄 통과, `fixture:7` 정상/복합 이상 확인, `test:r5` 전체 통과.
- 판정기 구역 판정: 내 목록(/my/notes)·단건 허용, 메모 전체 목록(/notes)·공지 쓰기·강사·미등록·기능 경로 거부 확인.
- 엔진을 통한 정상 쓰기·실제 강사 접속: 미검증(심판 환경에서 확인).

## 7단계 「평소와 다른 접속은 다시 확인합니다」

판정기 `src/decider.mjs`에 규칙을 더했습니다. 요청·응답 모양은 `docs/DECIDER_REQUEST.md` 계약 그대로이고, 계약에 있는 값(`signals`, `recentEvents`, `stepUp`)만 씁니다. `request.role`·`identity`·`device`·`geo`는 계약에 없어 읽지 않습니다.

- 입력 검사: 접속 정보 `signals`(`{source, region, network, hour}`)는 출처가 엔진이 보증한 값(`none` 실제 경로, `judge_fixture` 가상 사건)일 때만 신뢰합니다. 그 밖의 출처는 지역·네트워크·시각을 분석에 쓰지 않고, 빠지거나 불명확한 값을 임의의 정상값으로 채우지 않습니다. 위조한 클라이언트 헤더가 신뢰하는 접속 정보로 승격되지 않습니다.
- 규칙 `step_up_required`: 평소와 다른 네 신호(처음 보는 네트워크, 평소와 다른 지역, 한밤~새벽 시각, 짧은 시간의 대량 읽기) 중 둘 이상이 겹치면 `step_up`(추가 확인)을 요청합니다. 하나만으로는 허용이라 지역 하나로 영구 차단하지 않고, 겹친 신호는 사유로 로그에 남깁니다(토큰·본문은 기록하지 않음).
- 재인증 반영: 계약의 `stepUp`(`{verified, authAgeSeconds}`)으로 최근 15분(0~900초) 안에 재인증한 요청인지 확인합니다. `verified`가 참이어도 나이까지 보고, 오래되면 다시 `step_up`을 요구합니다. 엔진이 추가 확인 뒤 새 로그인으로 다시 보낸 요청을 판정기가 통과시키는 자리입니다.
- `RULE_IDS`는 `['device_registered', 'step_up_required']`이고, 모든 응답의 `ruleIds`는 이 목록 안의 이름만 씁니다. 기기 등록 규칙(6단계)은 그대로 유지됩니다.
- 단계 번호 7에 맞춰 빌드·배포 식별·자기 점검이 7단계를 받도록 했습니다. 자기 점검은 5·6단계와 같은 실제 요청만 보냅니다. 접속 분석과 재인증 규칙은 배포 서버로 보내는 요청이 아니라 심판이 가상 요청으로 확인하기 때문입니다.

확인 순서 (로컬 연습):

1. 자료실 폴더에서 `npm ci`를 한 번 실행합니다. (PowerShell에서는 `npm.cmd`)
2. `npm run decider:test`를 실행합니다. 네 줄(등록 기기 정상 요청 허용, 미등록 기기 거부, 복합 이상 접속 `step_up`, 재확인한 복합 이상 접속 허용)이 모두 `통과`여야 합니다.
3. `npm run fixture:7`로 정상 사건 `allow`와 복합 이상 사건 `step_up`을 다시 확인합니다. 로그가 번거로우면 `DECIDER_QUIET=1`로 끌 수 있습니다.

이 연습은 가상 요청으로 하며 심판 판정이 아닙니다. 평소와 다른 접속의 실제 자료 차단과 재인증 뒤 재판정은 반 엔진이 계약으로 연결된 환경에서 수행하므로, 로컬에서는 규칙만 시험하고 실제 자료 차단·재판정은 미실행으로 남깁니다. 미등록 기기 공격과 복합 이상 접속 사건은 심판이 가상 요청으로 보냅니다.

**7단계 확인 기록 (2026-10-14, 직접 실행한 것만 적었습니다)**
- 학생 PC에서 `npm run decider:test` 네 줄 모두 `통과`, `npm run fixture:7`에서 정상 `allow`·복합 이상 `step_up`을 확인했습니다.
- 실제 배포에서의 자료 차단·재인증 뒤 재판정: 미실행(심판 환경에서 확인).

## 6단계 「등록한 기기만 자료실에 들어옵니다」

판정기 `src/decider.mjs`에 규칙 하나를 넣었습니다. 요청·응답 모양은 `docs/DECIDER_REQUEST.md`의 계약 그대로이고, 계약에 있는 `request.deviceRegistered`만 씁니다.

- 규칙 `device_registered`: `deviceRegistered`가 정확히 `true`일 때만 `allow`(이유 코드 `approved`)입니다. `false`이거나 값이 없거나 다른 모양이면 `deny`(이유 코드 `device_not_registered`)입니다. 두 응답 모두 `ruleIds`에 `device_registered`를 적습니다.
- `RULE_IDS`는 `['device_registered']`입니다. 시작 틀의 `starter.deny`(모든 요청 거부)는 구현 전 표시였으므로 이 규칙으로 바꿨습니다.
- 단계 번호 6에 맞춰 빌드(`scripts/build-public.mjs`), 배포 식별(`scripts/deployment-identity.mjs`), 자기 점검(`src/attack-check.mjs`)이 6단계를 받도록 했습니다. 자기 점검은 5단계와 같은 실제 요청만 보냅니다. 기기 등록 규칙은 배포 서버로 보내는 요청이 아니라 심판이 가상 요청으로 확인하기 때문입니다.
- 사용자(`subjectId`)·기기(`deviceId`)를 브라우저 값으로 따로 믿지 않고, 인증서·CA·서명 키는 만들거나 저장소에 넣지 않았습니다. 이번 과정에는 따로 설치할 접속 프로그램이 없습니다.

확인 순서 (로컬 연습):

1. 자료실 폴더에서 `npm ci`를 한 번 실행합니다. (PowerShell에서는 `npm.cmd`)
2. `npm run decider:test`를 실행합니다.
3. 출력에 `통과 · 등록 기기의 정상 요청`(allow)과 `통과 · 미등록 기기의 가상 요청`(deny·`device_not_registered`)이 둘 다 보여야 합니다. 어느 한 줄이라도 `확인 필요`이면 `src/decider.mjs`의 규칙을 다시 봅니다.

이 시험은 가상 요청으로 하는 연습이며 심판 판정이 아닙니다. 실제 경로에서는 반 엔진의 릴레이가 미등록 기기를 판정기보다 먼저 막고, 미등록 기기 공격은 심판이 가상 요청으로 보냅니다.

**6단계 확인 기록 (2026-10-14, 직접 실행한 것만 적었습니다)**
- 학생 PC에서 `npm run decider:test`를 실행해 두 줄 모두 `통과`를 확인했습니다.

## 보너스 xdr-01 「무차별 로그인 공격을 잡아 냅니다」

Wazuh 로그인 경보 묶음(`xdr/fixtures/brute-force.json`, 28건)을 MITRE ATT&CK T1110 패턴과 맞춰 판단합니다. 판정기(`src/decider.mjs`)의 규칙은 고치지 않았습니다.

- `xdr/brute-force/patterns.json`: 근거가 있는 패턴 두 개(T1110.001 같은 주소의 로그인 실패 연속, T1110.003 여러 계정에 같은 비밀번호 대입). 기준값(15·3건, 5·2개)은 이번 경보에 맞춘 조정값입니다.
- `xdr/brute-force/decide.mjs`: 위 패턴을 맨 위 상수로 옮겨 적고 `decide(alert)`가 `{ action, confidence, reason }`을 돌려줍니다. 확신도 0.85 이상 block, 0.5 이상 alert, 그 아래 record. 다른 파일·패키지를 불러오지 않고, 파일 입출력과 네트워크 없이 혼자 계산합니다.
- `xdr/brute-force/respond.mjs`: block 경보만 출발 주소별 거부 규칙 후보(`blocklist.json`, 만료 시각·근거 경보 번호 포함)로 적고, block·alert를 `xdr/alerts.log`에 쌓습니다. 정상 경보에 나온 주소는 후보에서 뺍니다. `checkSource()`는 deny 또는 no_opinion만 돌려주는 확인 단계 부품입니다. 판정기 요청 계약(`docs/DECIDER_REQUEST.md`)에 출발 주소가 없어 실제 판정기에는 연결하지 않았습니다.
- `xdr/brute-force/read-alerts.mjs`: 시각·주소·계정·수준·설명만 뽑는 확인용 읽기 모듈입니다. `decide.mjs`는 이 파일을 불러오지 않습니다.

실행 방법:

```bash
npm run xdr:run -- brute-force        # result.json 생성 (PowerShell에서는 npm.cmd)
node xdr/brute-force/respond.mjs       # 차단 후보·알림 기록·다시 흘리기 확인
node xdr/brute-force/read-alerts.mjs   # 경보 건수와 뽑은 줄 수 확인
```

로컬 결과: block 10 · alert 9 · record 9, 정상 이벤트를 block한 경우 없음. 로컬 결과는 심판 판정이 아니며, 심판은 격리된 환경에서 같은 명령을 다시 실행합니다.

## 보너스 xdr-02 「웹 주입 공격을 잡아 냅니다」

Wazuh 웹 요청 경보 묶음(`xdr/fixtures/web-injection.json`, 26건)을 MITRE ATT&CK T1190(외부 공개 앱 악용) 패턴과 맞춰 판단합니다. 판정기(`src/decider.mjs`)의 규칙은 고치지 않았습니다.

- `xdr/web-injection/patterns.json`: 근거가 있는 패턴 네 개(SQL 구문 CWE-89, 스크립트 태그 CWE-79, 경로 거슬러 올라가기 CWE-22, 명령 구분자 CWE-78). 명령 구분자는 연속 요청 11번의 명확한 공격(wi-06)을 잡으려고 더했습니다. 반복 기준(5회·1회)은 이번 경보에 맞춘 조정값입니다.
- `xdr/web-injection/decide.mjs`: 위 패턴을 맨 위 상수로 옮겨 적고 `decide(alert)`가 `{ action, confidence, reason }`을 돌려줍니다. 공격 표기 구절과 반복 5회 이상이면 block, 표기 없이 T1190 표시만 있는 단발 요청은 alert, 그 밖은 record입니다. 'SQL'·'스크립트' 같은 단어 하나로는 맞추지 않습니다. 다른 파일·패키지를 불러오지 않고, 파일 입출력과 네트워크 없이 혼자 계산합니다.
- `xdr/web-injection/respond.mjs`: block 경보만 출발 주소별 거부 규칙 후보(`blocklist.json`, 만료 시각·근거 경보 번호 포함)로 적고, block·alert를 `xdr/alerts.log`에 `module=web-injection` 표시와 함께 쌓습니다. 판정기 요청 계약에 출발 주소가 없어 실제 판정기에는 연결하지 않았습니다.
- `xdr/web-injection/read-alerts.mjs`: 시각·주소·계정·수준·설명만 뽑는 확인용 읽기 모듈입니다. `decide.mjs`는 이 파일을 불러오지 않습니다.

실행 방법:

```bash
npm run xdr:run -- web-injection          # result.json 생성 (PowerShell에서는 npm.cmd)
node xdr/web-injection/respond.mjs         # 차단 후보·알림 기록·다시 흘리기 확인
node xdr/web-injection/read-alerts.mjs     # 경보 건수와 뽑은 줄 수 확인
```

로컬 결과: block 8 · alert 9 · record 9, 정상 이벤트를 block한 경우 없음. 로컬 결과는 심판 판정이 아니며, 심판은 격리된 환경에서 같은 명령을 다시 실행합니다.

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

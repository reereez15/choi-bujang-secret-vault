# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 시작 틀에 들어 있던 메모 네 건은 가상 자료이며 2단계에서 DB로 옮겼습니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 현재 상태: 4단계 「로그인해도 내 자료만 보이게 합니다」

**지금 작동하는 기능**
- 로그인 화면(`public/index.html`, `public/auth.js`)이 Supabase Auth 이메일·비밀번호 로그인과 로그아웃을 합니다. 비밀번호와 토큰은 공식 SDK(`/vendor/supabase.js`, 빌드가 `node_modules`에서 복사)만 다루고, 화면 코드에는 공개용(publishable) 키와 Project URL만 `public/auth-config.js`에 둡니다. 서버 전용 키로 보이면 화면이 SDK를 만들지 않고 거부합니다.
- 로그인한 사용자는 **자기** 가상 메모를 추가·수정·삭제합니다. 로그아웃하면 추가 창과 목록이 사라집니다.
- 자료 API(Vercel 서버 함수 `api/notes.js`, `api/notes/[id].js`, 본체 `src/notes-handler.mjs`와 `src/notes-store.mjs`):
  - `GET /api/notes`는 로그인 사용자 **본인** 메모의 배열 `[{id,title,body}]`, `POST /api/notes`는 `{id?,title,body}`를 받아 `{id}`를 돌려줍니다(id가 없으면 서버가 만듭니다).
  - `GET·PUT·DELETE /api/notes/:id`는 한 건 조회 `{id,title,body}`, 수정 `{title,body}`, 삭제입니다. 지운 뒤 GET은 404입니다.
  - 모든 요청은 DB에 닿기 전에 틀의 `src/verify-login.mjs`로 `Authorization` 토큰을 검사합니다. 토큰이 없거나 검사에 실패하면 자료 없이 401입니다.
  - **소유자 검사:** 한 건 GET·PUT·DELETE는 DB의 `owner_id`가 검증된 사용자 ID와 같을 때만 처리합니다. 남의 메모는 없는 메모와 똑같이 404로 답해서 그 id가 있는지도 알려 주지 않습니다. 수정은 기존 행의 소유자가 본인인지 확인하고 새 값에는 `owner_id`를 쓰지 않으며, 수정·삭제의 DB 쿼리에도 `owner_id` 조건을 함께 겁니다. 수정 본문에 내 ID가 아닌 `owner_id`를 담으면 403(`owner_change_forbidden`)으로 요청 전체를 거부합니다.
  - 추가할 때는 본문이나 URL의 `owner_id`·`userId`·`role`을 읽지 않고 검사로 확인된 사용자 ID를 `owner_id`로 저장합니다.
  - 메모의 `body`는 DB의 `content` 칸에 저장합니다.
- `aleph.config.json`은 `step` 4이고, `identityProvider`(발급자·공개키 주소·audience, 공개 값만)와 `allowedRoutes`(`GET /api/notes`, `POST /api/notes`, `GET /api/notes/:id`, `PUT /api/notes/:id`, `DELETE /api/notes/:id`)를 구현과 맞춰 적었습니다.
- 서버 함수는 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 **Vercel 환경변수**에서만 읽습니다. 두 값은 Vercel 프로젝트 Settings → Environment Variables 입력란에 직접 넣고(키는 Sensitive로), 코드·Git·채팅·로그에는 쓰지 않습니다.
- **DB 권한(두 번째 방어선):** 테이블 `vault_notes`는 RLS가 켜져 있고 정책이 네 개입니다. `authenticated`만 `SELECT`·`INSERT`·`UPDATE`·`DELETE` 권한을 갖고, 정책은 모두 `auth.uid() = owner_id`일 때만 허용합니다(SELECT·DELETE는 기존 행, INSERT는 새 행, UPDATE는 기존 행과 새 행 모두). `anon`과 `PUBLIC`에는 권한이 없습니다. 서버 함수가 쓰는 `service_role`은 RLS를 건너뛰고 권한을 그대로 갖습니다. 테이블과 권한을 만든 SQL 파일은 가상 메모 문장이 들어 있어 이 저장소에 두지 않았습니다.
- `data.json`과 `public/data.json`은 `{ "notes": [] }`입니다. 배포된 `/data.json`에는 메모가 없습니다.

**다시 실행하는 방법**
- 로컬 시험: `npm ci` 다음 `npm run test:r5`. 가짜 로그인과 가짜 DB로 하는 연습이며 실제 DB 연결이나 배포를 증명하지 않습니다.
- 배포 확인: 시크릿 창에서 짧은 주소를 열어 A로 로그인하면 A의 메모만, B로 로그인하면 B의 메모만 보이는지, 로그인 없이 `/api/notes`를 직접 열면 `unauthorized`로 거부되는지 봅니다. 상대 메모의 id로 읽기·수정·삭제를 보내면 404가 나와야 합니다.
- DB 확인: 로그인한 브라우저 Console에서 Supabase Data API(`…/rest/v1/vault_notes`)를 공개용 키와 로그인 토큰으로 직접 불러, 로그인 없이는 `permission denied`(401), 로그인하면 본인 행만 오는지 봅니다.
- 자기 점검: `npm run bundle`의 `src/attack-check.mjs`가 로그인 없는 GET·POST·PUT·DELETE, 위조한 토큰, `/data.json`, 응답의 키 노출 여부를 실제로 요청해 결과만 기록합니다. 상대 메모 접근과 소유자 변경 점검은 서로 다른 두 사용자의 실제 로그인 토큰이 있어야 보낼 수 있어서, 환경변수 `ATTACK_CHECK_TOKEN`(A)과 `ATTACK_CHECK_TOKEN_B`(B)가 둘 다 있을 때만 실행합니다. 이때 A의 임시 메모를 만들고 점검이 끝나면 지웁니다. 토큰이 없거나 배포 서버에 닿지 못한 점검은 "미실행"으로 적고, 토큰 값은 어디에도 적지 않습니다. 심판의 판정이 아닙니다.

**알려진 약점 (아직 남아 있음)**
- 메모를 다른 사용자와 공유하는 기능은 없습니다. 메모는 만든 사람 한 명만 다룹니다. 의도한 동작입니다.
- 이미 쓰인 id로 메모를 추가하면 409(`id_exists`)가 나옵니다. 남의 메모 id로 시도해도 같은 응답이라 "그 id가 존재한다"는 사실은 알 수 있습니다. 내용을 읽거나 덮어쓸 수는 없습니다.
- 2단계에서 넣은 가상 메모 네 건은 A 계정에, 시험 메모 한 건은 B 계정에 `owner_id`로 연결했습니다. 소유자가 비어 있는 메모는 없습니다.
- 로그인 토큰은 공식 SDK가 브라우저 저장소에 보관합니다(SDK 기본 동작). 페이지에 악성 스크립트가 실행되면 토큰이 노출될 수 있어서, 이 화면은 서버에서 받은 글을 `textContent`로만 그리고 외부 스크립트를 쓰지 않습니다.
- 지난 커밋과 옛 배포의 긴 주소(`…-해시-계정.vercel.app`)에는 1단계의 가상 메모가 남아 있습니다. 지금 파일을 바꿔도 이 이력은 지워지지 않습니다.

**4단계 확인 기록 (2026-10-06, 직접 확인한 것만 적었습니다)**
- DB에서 기존 가상 메모 네 건은 A 계정의 `owner_id`로, 시험 메모 한 건은 B 계정의 `owner_id`로 연결됐고 소유자가 없는 행은 0건임을 SQL Editor 조회로 확인했습니다.
- B로 로그인한 상태에서 A의 "과제" 메모 id로 GET·PUT·DELETE를 보냈을 때 모두 `404 {error: not_found}`였고, A 화면에서 네 건이 그대로 남아 있었습니다.
- 화면에서 A는 네 건, B는 "B의 시험 메모" 한 건만 보였습니다.
- DB 권한 적용 전후 `information_schema.role_table_grants`, `has_table_privilege`, 원본 ACL, RLS·정책 수를 대조했습니다. 적용 전에는 `anon`·`authenticated` 권한이 없고 정책이 0개, 적용 후에는 `anon` 권한 없음, `authenticated`는 `SELECT`·`INSERT`·`UPDATE`·`DELETE`만, 정책 4개, `service_role`은 변화 없음이었습니다. 적용 뒤에도 앱 화면은 A·B 모두 정상이었습니다.
- Data API를 직접 불러 로그인 없이는 `401`과 `permission denied for table vault_notes`(코드 42501), A로 로그인하면 네 행 모두 A의 `owner_id`, B로 로그인하면 B의 한 행뿐이었습니다. B가 A의 메모를 PATCH·DELETE로 직접 건드렸을 때 둘 다 빈 배열(바뀐 행 0건)이었습니다.
- 소유자 변경(403)과 상대 메모 추가 시도의 배포 확인은 **미실행**입니다. 로컬 시험과 가짜 DB 시나리오로만 확인했고, 두 토큰을 넘긴 `npm run bundle`이 배포에서 확인합니다.

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

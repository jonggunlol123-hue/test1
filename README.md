# 골드문 FiveM 조직 관리 포털

업로드된 기존 HTML 디자인을 기반으로 Node.js/Express와 PostgreSQL을 연결한 Render 배포용 프로젝트입니다.

## 기능
- 기존 골드문 검정/금색 UI 및 대시보드, 조직원, 직급, 장부, 품목, 거래내역 CSV, 대출 관리
- 서버에서 bcrypt 비밀번호 검증 및 해시 저장
- PostgreSQL 기반 로그인 세션 및 업무 데이터 저장
- 로그인 rate limit, HTTP 보안 헤더, HttpOnly/SameSite 쿠키, 운영 환경 Secure 쿠키
- 로그인 화면에서 데모 초기 계정 안내 제거
- 관리자 비밀번호 변경 및 운영자용 CLI 재설정

## Render 배포
1. 이 폴더를 GitHub 저장소에 올립니다.
2. Render에서 Blueprint로 저장소를 연결하고 `render.yaml`을 적용합니다. 또는 Node 웹 서비스와 PostgreSQL을 별도로 생성합니다.
3. 서비스 환경변수에서 `ADMIN_USERNAME`, `ADMIN_PASSWORD`를 설정합니다. 비밀번호는 12자 이상의 고유한 값으로 사용하세요. `SESSION_SECRET`은 Render가 생성하도록 합니다.
4. `DATABASE_URL`은 Render PostgreSQL의 Internal Database URL을 사용하도록 설정합니다.
5. 배포 후 `/healthz`가 `{"status":"ok"}`를 반환하는지 확인합니다.

최초 관리자 생성은 `ADMIN_USERNAME`/`ADMIN_PASSWORD`가 지정된 경우에만 진행됩니다. 해당 username이 이미 있으면 기존 비밀번호는 덮어쓰지 않습니다. 초기 계정이 생성된 뒤 Render 환경변수에서 `ADMIN_PASSWORD`를 제거해도 로그인은 DB 해시를 기준으로 동작합니다.

## 로컬 실행
Node.js 20 이상 및 PostgreSQL이 필요합니다.

```bash
cp .env.example .env
# .env에서 DATABASE_URL, SESSION_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD 설정
npm install
npm start
```

브라우저에서 `http://localhost:3000`으로 접속합니다.

## 관리자 비밀번호 재설정
서비스의 환경변수 또는 로컬 `.env`에 `RESET_ADMIN_USERNAME`과 `RESET_ADMIN_PASSWORD`(12자 이상)를 설정한 뒤 DB에 접근 가능한 환경에서 실행합니다.

```bash
npm run admin:reset
```

성공 여부를 확인한 뒤 재설정용 환경변수는 제거하세요. 기존 비밀번호를 알 필요 없이 DB에 저장된 bcrypt 해시가 새 값으로 교체됩니다.

## 중요 보안 안내
- `.env`나 실제 비밀번호를 GitHub에 올리지 마세요.
- Render 운영 서비스는 HTTPS 및 `Secure` 세션 쿠키를 사용합니다.
- PostgreSQL 연결 문자열은 비밀정보로 취급하세요.
- Tailwind CSS는 원본 디자인 유지를 위해 CDN을 사용합니다. 높은 보안 수준의 CSP를 적용하려면 CSS/스크립트를 빌드 파일로 분리하고 정책을 조정해야 합니다.
- 데이터는 단일 JSONB 상태 문서로 저장됩니다. 소규모 조직 포털에 맞춘 호환 중심 구현이며, 동시 다중 관리자 편집이 많아지면 각 기능을 개별 테이블로 분리하는 것을 권장합니다.
- 배포 전 테스트 서버에서 로그인, 새로고침 후 데이터 유지, 로그아웃, 비밀번호 변경, CSV 내보내기를 확인하세요.

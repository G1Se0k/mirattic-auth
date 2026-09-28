# Mirattic Auth — 기획안

## 1. 목적
Mirattic Auth는 Mirattic 서비스 전체에서 사용하는 중앙 계정/인증 서비스다.

목표:
- Sync, Flow 등에서 하나의 Mirattic 계정 사용
- 회원가입/비밀번호 재설정 중복 구현 제거
- 서비스 간 SSO
- 향후 Google / Apple 로그인 확장
- 세션과 연결된 로그인 수단을 한곳에서 관리

## 2. 비목표
Auth는 다음을 중앙화하지 않는다:
- Sync의 친구/방/채팅
- Flow의 워크스페이스/이슈/프로젝트
- 서비스별 권한
- 결제/구독
- 서비스 전용 설정

Auth는 "누구인가"를 담당하고, 제품은 "그 사용자가 무엇을 할 수 있는가"를 담당한다.

## 3. 전체 구조
```text
                   auth.mirattic.com
                 ┌──────────────────┐
                 │  Mirattic Auth   │
                 │ OAuth2 / OIDC    │
                 │ Account / Login  │
                 └────────┬─────────┘
                          │
          ┌───────────────┼────────────────┐
          │               │                │
          ▼               ▼                ▼
   Mirattic Sync     Mirattic Flow    Future Services
      Sync DB           Flow DB          Own DB
```

서비스는 Auth DB를 직접 조회하지 않는다.

## 4. 사용자 흐름
### 회원가입
사용자 → Auth 가입 → Mirattic UID 생성 → 로그인 가능

### 서비스 로그인
서비스 → `auth.mirattic.com/authorize` → 로그인/SSO → authorization code → PKCE token exchange → 로그인 완료

### SSO
Auth 브라우저 세션이 살아 있으면 다른 Mirattic 서비스에서 비밀번호 재입력 없이 로그인한다.

## 5. 계정 모델
```text
users
└─ identities
   ├─ LOCAL
   ├─ GOOGLE
   └─ APPLE
```

- 전역 UID는 UUID
- 모든 서비스에서 같은 OIDC `sub`
- 이메일/provider ID에서 UID를 파생하지 않음
- 이메일은 identity 속성이고 영구 PK가 아님

## 6. 토큰 전략
- ID Token: JWT
- Access Token: JWT
- Refresh Token: opaque random token
- Signing: asymmetric key
- Public keys: JWKS
- 서비스는 JWKS로 검증하고 매 요청마다 Auth에 문의하지 않음

## 7. 초기 기능
- 이메일/비밀번호 회원가입
- 로그인/로그아웃
- 비밀번호 재설정
- Authorization endpoint
- Token endpoint
- UserInfo endpoint
- JWKS
- OIDC discovery
- refresh rotation/revoke
- 세션 관리
- Sync/Flow client 등록

## 8. 향후 기능
- Google 로그인
- Apple 로그인
- 연결된 로그인 수단 관리
- MFA / Passkey
- 계정 센터
- 로그인 이력
- 위험 로그인 탐지

## 9. MVP 완료 기준
1. Auth에서 계정 생성 가능
2. 비밀번호 재설정 가능
3. Sync가 OIDC로 로그인 가능
4. Flow도 같은 UID로 로그인 가능
5. 서비스 간 SSO 가능
6. 서비스가 Auth DB를 직접 조회하지 않음
7. 각 서비스가 access token을 독립 검증 가능
8. refresh rotation/revoke 동작
9. 계정 삭제/비활성화 정책 문서화

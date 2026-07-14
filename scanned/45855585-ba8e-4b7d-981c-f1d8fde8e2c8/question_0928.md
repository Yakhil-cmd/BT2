# Q928: auth-profile via index 928

## Question
Can an unprivileged attacker entering through the persisted preference reload in `index` (packages/core/src/components/Auth/index.ts) control private preference values migrated from localStorage with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/components/Auth/index.ts` / `index`
- Entrypoint: persisted preference reload
- Attacker controls: private preference values migrated from localStorage; with a redirected remote resource
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

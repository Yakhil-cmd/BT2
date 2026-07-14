# Q1367: auth-profile via if 1367

## Question
Can an unprivileged attacker entering through the passphrase prompt workflow in `if` (packages/gui/src/electron/prefs.ts) control prompt reason mismatch with a redirected remote resource and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/prefs.ts` / `if`
- Entrypoint: passphrase prompt workflow
- Attacker controls: prompt reason mismatch; with a redirected remote resource
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

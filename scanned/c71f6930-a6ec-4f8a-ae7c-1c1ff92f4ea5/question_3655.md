# Q3655: auth-profile via setValue 3655

## Question
Can an unprivileged attacker entering through the auto-login startup path in `setValue` (packages/core/src/hooks/usePersistState.ts) control stale fingerprint stored in prefs or Redux state with a duplicate identifier and drive the sequence download or render content -> trigger linked wallet action so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/usePersistState.ts` / `setValue`
- Entrypoint: auto-login startup path
- Attacker controls: stale fingerprint stored in prefs or Redux state; with a duplicate identifier
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

# Q2767: auth-profile via useEnableAutoLogin 2767

## Question
Can an unprivileged attacker entering through the passphrase prompt workflow in `useEnableAutoLogin` (packages/gui/src/hooks/useEnableAutoLogin.ts) control rapid logout/login/profile switch timing with precision-boundary values and drive the sequence preview -> mutate controlled state -> confirm so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/hooks/useEnableAutoLogin.ts` / `useEnableAutoLogin`
- Entrypoint: passphrase prompt workflow
- Attacker controls: rapid logout/login/profile switch timing; with precision-boundary values
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

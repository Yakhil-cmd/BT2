# Q839: auth-profile via AuthContext 839

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `AuthContext` (packages/core/src/components/Auth/AuthProvider.tsx) control rapid logout/login/profile switch timing with a redirected remote resource and drive the sequence open notification -> resolve details -> execute so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/components/Auth/AuthProvider.tsx` / `AuthContext`
- Entrypoint: keyring migration prompt
- Attacker controls: rapid logout/login/profile switch timing; with a redirected remote resource
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

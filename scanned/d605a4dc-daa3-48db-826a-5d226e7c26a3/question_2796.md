# Q2796: auth-profile via index 2796

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `index` (packages/core/src/components/Auth/index.ts) control stale fingerprint stored in prefs or Redux state with hidden Unicode characters and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/components/Auth/index.ts` / `index`
- Entrypoint: profile/fingerprint switch
- Attacker controls: stale fingerprint stored in prefs or Redux state; with hidden Unicode characters
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

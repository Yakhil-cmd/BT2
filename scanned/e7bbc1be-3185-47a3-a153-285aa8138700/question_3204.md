# Q3204: auth-profile via CrCatAuthorizedProviders 3204

## Question
Can an unprivileged attacker entering through the persisted preference reload in `CrCatAuthorizedProviders` (packages/wallets/src/components/crCat/CrCatAuthorizedProviders.tsx) control stale fingerprint stored in prefs or Redux state with a delayed metadata fetch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/wallets/src/components/crCat/CrCatAuthorizedProviders.tsx` / `CrCatAuthorizedProviders`
- Entrypoint: persisted preference reload
- Attacker controls: stale fingerprint stored in prefs or Redux state; with a delayed metadata fetch
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

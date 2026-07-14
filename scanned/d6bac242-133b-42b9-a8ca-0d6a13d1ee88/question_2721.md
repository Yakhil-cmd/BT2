# Q2721: auth-profile via usePersistState 2721

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `usePersistState` (packages/core/src/hooks/usePersistState.ts) control stale fingerprint stored in prefs or Redux state after a profile switch and drive the sequence select -> edit backing object -> submit so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/usePersistState.ts` / `usePersistState`
- Entrypoint: profile/fingerprint switch
- Attacker controls: stale fingerprint stored in prefs or Redux state; after a profile switch
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

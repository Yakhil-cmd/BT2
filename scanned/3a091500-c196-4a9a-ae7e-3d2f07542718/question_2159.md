# Q2159: auth-profile via getLoggedInFingerprint 2159

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `getLoggedInFingerprint` (packages/gui/src/electron/api/getLoggedInFingerprint.ts) control stale fingerprint stored in prefs or Redux state after canceling and reopening the dialog and drive the sequence load persisted state -> render approval -> execute command so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/api/getLoggedInFingerprint.ts` / `getLoggedInFingerprint`
- Entrypoint: keyring migration prompt
- Attacker controls: stale fingerprint stored in prefs or Redux state; after canceling and reopening the dialog
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

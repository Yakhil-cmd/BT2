# Q643: auth-profile via getPreferencesPath 643

## Question
Can an unprivileged attacker entering through the passphrase prompt workflow in `getPreferencesPath` (packages/gui/src/electron/utils/privatePreferences.ts) control prompt reason mismatch with a cached permission entry and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/utils/privatePreferences.ts` / `getPreferencesPath`
- Entrypoint: passphrase prompt workflow
- Attacker controls: prompt reason mismatch; with a cached permission entry
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

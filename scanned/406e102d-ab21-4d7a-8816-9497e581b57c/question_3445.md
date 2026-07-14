# Q3445: auth-profile via savePreferences 3445

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `savePreferences` (packages/gui/src/electron/utils/privatePreferences.ts) control dismiss/cancel sequence during pending RPC action with a redirected remote resource and drive the sequence download or render content -> trigger linked wallet action so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/utils/privatePreferences.ts` / `savePreferences`
- Entrypoint: profile/fingerprint switch
- Attacker controls: dismiss/cancel sequence during pending RPC action; with a redirected remote resource
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

# Q290: auth-profile via getLoggedInFingerprint 290

## Question
Can an unprivileged attacker entering through the persisted preference reload in `getLoggedInFingerprint` (packages/gui/src/electron/api/getLoggedInFingerprint.ts) control dismiss/cancel sequence during pending RPC action after a profile switch and drive the sequence select -> edit backing object -> submit so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/api/getLoggedInFingerprint.ts` / `getLoggedInFingerprint`
- Entrypoint: persisted preference reload
- Attacker controls: dismiss/cancel sequence during pending RPC action; after a profile switch
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

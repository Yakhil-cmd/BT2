# Q2625: auth-profile via Fingerprint 2625

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `Fingerprint` (packages/api/src/@types/Fingerprint.ts) control rapid logout/login/profile switch timing with reordered RPC events and drive the sequence connect -> approve -> switch context -> execute so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api/src/@types/Fingerprint.ts` / `Fingerprint`
- Entrypoint: profile/fingerprint switch
- Attacker controls: rapid logout/login/profile switch timing; with reordered RPC events
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

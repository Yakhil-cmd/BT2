# Q712: auth-profile via useCurrentFingerprintSettings 712

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `useCurrentFingerprintSettings` (packages/api-react/src/hooks/useCurrentFingerprintSettings.ts) control stale fingerprint stored in prefs or Redux state after a failed RPC response and drive the sequence fetch -> cache -> refresh -> submit so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api-react/src/hooks/useCurrentFingerprintSettings.ts` / `useCurrentFingerprintSettings`
- Entrypoint: profile/fingerprint switch
- Attacker controls: stale fingerprint stored in prefs or Redux state; after a failed RPC response
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

# Q3093: auth-profile via getLoggedInFingerprint 3093

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `getLoggedInFingerprint` (packages/gui/src/electron/api/getLoggedInFingerprint.ts) control prompt reason mismatch with a stale Redux cache and drive the sequence download or render content -> trigger linked wallet action so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/api/getLoggedInFingerprint.ts` / `getLoggedInFingerprint`
- Entrypoint: profile/fingerprint switch
- Attacker controls: prompt reason mismatch; with a stale Redux cache
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

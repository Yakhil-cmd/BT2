# Q1224: auth-profile via getLoggedInFingerprint 1224

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `getLoggedInFingerprint` (packages/gui/src/electron/api/getLoggedInFingerprint.ts) control private preference values migrated from localStorage with a duplicate identifier and drive the sequence validate input -> normalize payload -> call RPC so the GUI would leave modal approval state alive across account changes, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/api/getLoggedInFingerprint.ts` / `getLoggedInFingerprint`
- Entrypoint: keyring migration prompt
- Attacker controls: private preference values migrated from localStorage; with a duplicate identifier
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

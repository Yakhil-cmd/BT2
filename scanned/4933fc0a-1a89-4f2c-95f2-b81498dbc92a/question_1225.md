# Q1225: auth-profile via getLoggedInFingerprint 1225

## Question
Can an unprivileged attacker entering through the persisted preference reload in `getLoggedInFingerprint` (packages/gui/src/electron/api/getLoggedInFingerprint.ts) control rapid logout/login/profile switch timing with a duplicate identifier and drive the sequence validate input -> normalize payload -> call RPC so the GUI would leave modal approval state alive across account changes, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/api/getLoggedInFingerprint.ts` / `getLoggedInFingerprint`
- Entrypoint: persisted preference reload
- Attacker controls: rapid logout/login/profile switch timing; with a duplicate identifier
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

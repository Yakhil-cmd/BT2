# Q2301: auth-profile via readPrefs 2301

## Question
Can an unprivileged attacker entering through the persisted preference reload in `readPrefs` (packages/gui/src/electron/prefs.ts) control rapid logout/login/profile switch timing during a pending modal confirmation and drive the sequence open notification -> resolve details -> execute so the GUI would leave modal approval state alive across account changes, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/prefs.ts` / `readPrefs`
- Entrypoint: persisted preference reload
- Attacker controls: rapid logout/login/profile switch timing; during a pending modal confirmation
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

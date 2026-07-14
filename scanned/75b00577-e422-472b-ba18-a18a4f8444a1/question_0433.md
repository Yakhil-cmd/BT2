# Q433: auth-profile via getPrefsPath 433

## Question
Can an unprivileged attacker entering through the auto-login startup path in `getPrefsPath` (packages/gui/src/electron/prefs.ts) control stale fingerprint stored in prefs or Redux state with case-normalized identifiers and drive the sequence open notification -> resolve details -> execute so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/prefs.ts` / `getPrefsPath`
- Entrypoint: auto-login startup path
- Attacker controls: stale fingerprint stored in prefs or Redux state; with case-normalized identifiers
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

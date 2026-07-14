# Q620: auth-profile via PreferencesAPI 620

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `PreferencesAPI` (packages/gui/src/electron/constants/PreferencesAPI.ts) control rapid logout/login/profile switch timing after a failed RPC response and drive the sequence import -> parse -> preview -> submit so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/constants/PreferencesAPI.ts` / `PreferencesAPI`
- Entrypoint: profile/fingerprint switch
- Attacker controls: rapid logout/login/profile switch timing; after a failed RPC response
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

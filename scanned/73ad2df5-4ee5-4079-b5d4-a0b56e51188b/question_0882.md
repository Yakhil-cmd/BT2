# Q882: auth-profile via RemovePassphrasePrompt 882

## Question
Can an unprivileged attacker entering through the persisted preference reload in `RemovePassphrasePrompt` (packages/gui/src/components/settings/RemovePassphrasePrompt.tsx) control rapid logout/login/profile switch timing with a cached permission entry and drive the sequence download or render content -> trigger linked wallet action so the GUI would leave modal approval state alive across account changes, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/RemovePassphrasePrompt.tsx` / `RemovePassphrasePrompt`
- Entrypoint: persisted preference reload
- Attacker controls: rapid logout/login/profile switch timing; with a cached permission entry
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

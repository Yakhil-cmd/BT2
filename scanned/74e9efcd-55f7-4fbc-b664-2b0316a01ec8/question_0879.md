# Q879: auth-profile via ChangePassphrasePrompt 879

## Question
Can an unprivileged attacker entering through the auto-login startup path in `ChangePassphrasePrompt` (packages/gui/src/components/settings/ChangePassphrasePrompt.tsx) control private preference values migrated from localStorage with a redirected remote resource and drive the sequence download or render content -> trigger linked wallet action so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/ChangePassphrasePrompt.tsx` / `ChangePassphrasePrompt`
- Entrypoint: auto-login startup path
- Attacker controls: private preference values migrated from localStorage; with a redirected remote resource
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

# Q1817: auth-profile via validateDialog 1817

## Question
Can an unprivileged attacker entering through the auto-login startup path in `validateDialog` (packages/gui/src/components/settings/SetPassphrasePrompt.tsx) control private preference values migrated from localStorage after a profile switch and drive the sequence fetch -> cache -> refresh -> submit so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/SetPassphrasePrompt.tsx` / `validateDialog`
- Entrypoint: auto-login startup path
- Attacker controls: private preference values migrated from localStorage; after a profile switch
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

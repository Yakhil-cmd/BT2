# Q1647: auth-profile via setValue 1647

## Question
Can an unprivileged attacker entering through the passphrase prompt workflow in `setValue` (packages/api-react/src/hooks/useFingerprintSettings.ts) control stale fingerprint stored in prefs or Redux state after canceling and reopening the dialog and drive the sequence select -> edit backing object -> submit so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api-react/src/hooks/useFingerprintSettings.ts` / `setValue`
- Entrypoint: passphrase prompt workflow
- Attacker controls: stale fingerprint stored in prefs or Redux state; after canceling and reopening the dialog
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

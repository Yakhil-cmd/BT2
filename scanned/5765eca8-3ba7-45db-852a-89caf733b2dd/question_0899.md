# Q899: auth-profile via useEnableAutoLogin 899

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `useEnableAutoLogin` (packages/gui/src/hooks/useEnableAutoLogin.ts) control prompt reason mismatch after a failed RPC response and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/hooks/useEnableAutoLogin.ts` / `useEnableAutoLogin`
- Entrypoint: profile/fingerprint switch
- Attacker controls: prompt reason mismatch; after a failed RPC response
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

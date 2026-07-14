# Q880: auth-profile via StyledCard 880

## Question
Can an unprivileged attacker entering through the passphrase prompt workflow in `StyledCard` (packages/gui/src/components/settings/ProfileAdd.tsx) control dismiss/cancel sequence during pending RPC action after a network switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/ProfileAdd.tsx` / `StyledCard`
- Entrypoint: passphrase prompt workflow
- Attacker controls: dismiss/cancel sequence during pending RPC action; after a network switch
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

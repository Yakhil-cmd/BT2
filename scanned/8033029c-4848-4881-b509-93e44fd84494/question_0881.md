# Q881: auth-profile via StyledCard 881

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `StyledCard` (packages/gui/src/components/settings/ProfileView.tsx) control dismiss/cancel sequence during pending RPC action with reordered RPC events and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/ProfileView.tsx` / `StyledCard`
- Entrypoint: profile/fingerprint switch
- Attacker controls: dismiss/cancel sequence during pending RPC action; with reordered RPC events
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

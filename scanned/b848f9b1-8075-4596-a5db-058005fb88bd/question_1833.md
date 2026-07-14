# Q1833: auth-profile via useEnableAutoLogin 1833

## Question
Can an unprivileged attacker entering through the auto-login startup path in `useEnableAutoLogin` (packages/gui/src/hooks/useEnableAutoLogin.ts) control dismiss/cancel sequence during pending RPC action after a network switch and drive the sequence load persisted state -> render approval -> execute command so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/hooks/useEnableAutoLogin.ts` / `useEnableAutoLogin`
- Entrypoint: auto-login startup path
- Attacker controls: dismiss/cancel sequence during pending RPC action; after a network switch
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

# Q1646: auth-profile via useCurrentFingerprintSettings 1646

## Question
Can an unprivileged attacker entering through the auto-login startup path in `useCurrentFingerprintSettings` (packages/api-react/src/hooks/useCurrentFingerprintSettings.ts) control prompt reason mismatch after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api-react/src/hooks/useCurrentFingerprintSettings.ts` / `useCurrentFingerprintSettings`
- Entrypoint: auto-login startup path
- Attacker controls: prompt reason mismatch; after a network switch
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

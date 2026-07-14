# Q2720: auth-profile via handleGenerateNamespace 2720

## Question
Can an unprivileged attacker entering through the auto-login startup path in `handleGenerateNamespace` (packages/core/src/hooks/usePersist.ts) control private preference values migrated from localStorage through a batch of rapid user-accessible actions and drive the sequence connect -> approve -> switch context -> execute so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/usePersist.ts` / `handleGenerateNamespace`
- Entrypoint: auto-login startup path
- Attacker controls: private preference values migrated from localStorage; through a batch of rapid user-accessible actions
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

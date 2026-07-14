# Q3682: auth-profile via handleSubmit 3682

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `handleSubmit` (packages/gui/src/components/settings/ProfileAdd.tsx) control private preference values migrated from localStorage after a profile switch and drive the sequence open notification -> resolve details -> execute so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/ProfileAdd.tsx` / `handleSubmit`
- Entrypoint: profile/fingerprint switch
- Attacker controls: private preference values migrated from localStorage; after a profile switch
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

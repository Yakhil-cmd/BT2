# Q883: auth-profile via SetPassphrasePrompt 883

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `SetPassphrasePrompt` (packages/gui/src/components/settings/SetPassphrasePrompt.tsx) control dismiss/cancel sequence during pending RPC action through a batch of rapid user-accessible actions and drive the sequence validate input -> normalize payload -> call RPC so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/SetPassphrasePrompt.tsx` / `SetPassphrasePrompt`
- Entrypoint: profile/fingerprint switch
- Attacker controls: dismiss/cancel sequence during pending RPC action; through a batch of rapid user-accessible actions
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

# Q3366: auth-profile via PassphrasePromptReason 3366

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `PassphrasePromptReason` (packages/api/src/constants/PassphrasePromptReason.ts) control dismiss/cancel sequence during pending RPC action with a delayed metadata fetch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api/src/constants/PassphrasePromptReason.ts` / `PassphrasePromptReason`
- Entrypoint: profile/fingerprint switch
- Attacker controls: dismiss/cancel sequence during pending RPC action; with a delayed metadata fetch
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

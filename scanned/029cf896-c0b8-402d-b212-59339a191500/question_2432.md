# Q2432: auth-profile via PassphrasePromptReason 2432

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `PassphrasePromptReason` (packages/api/src/constants/PassphrasePromptReason.ts) control prompt reason mismatch after a profile switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would migrate untrusted localStorage values into security-sensitive prefs, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api/src/constants/PassphrasePromptReason.ts` / `PassphrasePromptReason`
- Entrypoint: keyring migration prompt
- Attacker controls: prompt reason mismatch; after a profile switch
- Exploit idea: migrate untrusted localStorage values into security-sensitive prefs
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

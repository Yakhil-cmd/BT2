# Q564: auth-profile via PassphrasePromptReason 564

## Question
Can an unprivileged attacker entering through the passphrase prompt workflow in `PassphrasePromptReason` (packages/api/src/constants/PassphrasePromptReason.ts) control private preference values migrated from localStorage with precision-boundary values and drive the sequence open notification -> resolve details -> execute so the GUI would leave modal approval state alive across account changes, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/api/src/constants/PassphrasePromptReason.ts` / `PassphrasePromptReason`
- Entrypoint: passphrase prompt workflow
- Attacker controls: private preference values migrated from localStorage; with precision-boundary values
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

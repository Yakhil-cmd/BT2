# Q3681: auth-profile via handleCancel 3681

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `handleCancel` (packages/gui/src/components/settings/ChangePassphrasePrompt.tsx) control dismiss/cancel sequence during pending RPC action after a failed RPC response and drive the sequence open notification -> resolve details -> execute so the GUI would leave modal approval state alive across account changes, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/ChangePassphrasePrompt.tsx` / `handleCancel`
- Entrypoint: keyring migration prompt
- Attacker controls: dismiss/cancel sequence during pending RPC action; after a failed RPC response
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

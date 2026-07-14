# Q3684: auth-profile via handleKeyDown 3684

## Question
Can an unprivileged attacker entering through the auto-login startup path in `handleKeyDown` (packages/gui/src/components/settings/RemovePassphrasePrompt.tsx) control rapid logout/login/profile switch timing after a failed RPC response and drive the sequence validate input -> normalize payload -> call RPC so the GUI would leave modal approval state alive across account changes, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/RemovePassphrasePrompt.tsx` / `handleKeyDown`
- Entrypoint: auto-login startup path
- Attacker controls: rapid logout/login/profile switch timing; after a failed RPC response
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

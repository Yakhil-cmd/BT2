# Q1535: auth-profile via if 1535

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `if` (packages/core/src/hooks/useAuth.ts) control dismiss/cancel sequence during pending RPC action after a failed RPC response and drive the sequence preview -> mutate controlled state -> confirm so the GUI would complete a pending signing/spend action under a different fingerprint than the prompt showed, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/useAuth.ts` / `if`
- Entrypoint: keyring migration prompt
- Attacker controls: dismiss/cancel sequence during pending RPC action; after a failed RPC response
- Exploit idea: complete a pending signing/spend action under a different fingerprint than the prompt showed
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

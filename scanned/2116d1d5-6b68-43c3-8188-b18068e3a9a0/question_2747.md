# Q2747: auth-profile via handleSubmit 2747

## Question
Can an unprivileged attacker entering through the persisted preference reload in `handleSubmit` (packages/gui/src/components/settings/ChangePassphrasePrompt.tsx) control prompt reason mismatch with hidden Unicode characters and drive the sequence fetch -> cache -> refresh -> submit so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/ChangePassphrasePrompt.tsx` / `handleSubmit`
- Entrypoint: persisted preference reload
- Attacker controls: prompt reason mismatch; with hidden Unicode characters
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

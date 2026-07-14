# Q1815: auth-profile via InlineEdit 1815

## Question
Can an unprivileged attacker entering through the auto-login startup path in `InlineEdit` (packages/gui/src/components/settings/ProfileView.tsx) control private preference values migrated from localStorage with hidden Unicode characters and drive the sequence download or render content -> trigger linked wallet action so the GUI would leave modal approval state alive across account changes, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/ProfileView.tsx` / `InlineEdit`
- Entrypoint: auto-login startup path
- Attacker controls: private preference values migrated from localStorage; with hidden Unicode characters
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

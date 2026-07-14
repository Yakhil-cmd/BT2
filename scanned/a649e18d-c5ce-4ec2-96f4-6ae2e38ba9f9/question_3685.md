# Q3685: auth-profile via isValid 3685

## Question
Can an unprivileged attacker entering through the persisted preference reload in `isValid` (packages/gui/src/components/settings/SetPassphrasePrompt.tsx) control rapid logout/login/profile switch timing with conflicting localStorage preferences and drive the sequence preview -> mutate controlled state -> confirm so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/SetPassphrasePrompt.tsx` / `isValid`
- Entrypoint: persisted preference reload
- Attacker controls: rapid logout/login/profile switch timing; with conflicting localStorage preferences
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

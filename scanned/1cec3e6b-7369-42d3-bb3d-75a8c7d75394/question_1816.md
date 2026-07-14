# Q1816: auth-profile via handleSubmit 1816

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `handleSubmit` (packages/gui/src/components/settings/RemovePassphrasePrompt.tsx) control prompt reason mismatch with reordered RPC events and drive the sequence import -> parse -> preview -> submit so the GUI would reuse auto-login or persisted auth state after logout/profile switch, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/components/settings/RemovePassphrasePrompt.tsx` / `handleSubmit`
- Entrypoint: keyring migration prompt
- Attacker controls: prompt reason mismatch; with reordered RPC events
- Exploit idea: reuse auto-login or persisted auth state after logout/profile switch
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

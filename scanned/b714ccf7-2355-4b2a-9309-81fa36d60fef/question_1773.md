# Q1773: auth-profile via AuthProvider 1773

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `AuthProvider` (packages/core/src/components/Auth/AuthProvider.tsx) control prompt reason mismatch during a pending modal confirmation and drive the sequence load persisted state -> render approval -> execute command so the GUI would leave modal approval state alive across account changes, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/components/Auth/AuthProvider.tsx` / `AuthProvider`
- Entrypoint: profile/fingerprint switch
- Attacker controls: prompt reason mismatch; during a pending modal confirmation
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

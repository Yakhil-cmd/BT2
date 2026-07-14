# Q1786: auth-profile via if 1786

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `if` (packages/core/src/hooks/usePersist.ts) control prompt reason mismatch with precision-boundary values and drive the sequence download or render content -> trigger linked wallet action so the GUI would leave modal approval state alive across account changes, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/usePersist.ts` / `if`
- Entrypoint: profile/fingerprint switch
- Attacker controls: prompt reason mismatch; with precision-boundary values
- Exploit idea: leave modal approval state alive across account changes
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

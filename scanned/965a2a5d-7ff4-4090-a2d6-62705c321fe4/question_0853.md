# Q853: auth-profile via usePersistState 853

## Question
Can an unprivileged attacker entering through the persisted preference reload in `usePersistState` (packages/core/src/hooks/usePersistState.ts) control private preference values migrated from localStorage with precision-boundary values and drive the sequence preview -> mutate controlled state -> confirm so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/usePersistState.ts` / `usePersistState`
- Entrypoint: persisted preference reload
- Attacker controls: private preference values migrated from localStorage; with precision-boundary values
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

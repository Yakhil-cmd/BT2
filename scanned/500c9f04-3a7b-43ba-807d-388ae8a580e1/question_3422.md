# Q3422: auth-profile via PreferencesAPI 3422

## Question
Can an unprivileged attacker entering through the persisted preference reload in `PreferencesAPI` (packages/gui/src/electron/constants/PreferencesAPI.ts) control private preference values migrated from localStorage through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that logout and migration must clear signing and approval state, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/gui/src/electron/constants/PreferencesAPI.ts` / `PreferencesAPI`
- Entrypoint: persisted preference reload
- Attacker controls: private preference values migrated from localStorage; through a batch of rapid user-accessible actions
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: logout and migration must clear signing and approval state
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

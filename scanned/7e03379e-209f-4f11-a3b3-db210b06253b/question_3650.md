# Q3650: auth-profile via promptForKeyringMigration 3650

## Question
Can an unprivileged attacker entering through the profile/fingerprint switch in `promptForKeyringMigration` (packages/core/src/hooks/useKeyringMigrationPrompt.tsx) control stale fingerprint stored in prefs or Redux state with a stale Redux cache and drive the sequence open notification -> resolve details -> execute so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/useKeyringMigrationPrompt.tsx` / `promptForKeyringMigration`
- Entrypoint: profile/fingerprint switch
- Attacker controls: stale fingerprint stored in prefs or Redux state; with a stale Redux cache
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: auth, fingerprint, prompt reason, route access, and pending action context must be atomic across profile changes
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

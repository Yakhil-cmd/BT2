# Q852: auth-profile via usePersist 852

## Question
Can an unprivileged attacker entering through the keyring migration prompt in `usePersist` (packages/core/src/hooks/usePersist.ts) control dismiss/cancel sequence during pending RPC action after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would skip a required passphrase prompt because prompt reason or route guard becomes stale, violating the invariant that persisted preferences must not grant authority without current authentication, leading to Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass?

## Target
- File/function: `packages/core/src/hooks/usePersist.ts` / `usePersist`
- Entrypoint: keyring migration prompt
- Attacker controls: dismiss/cancel sequence during pending RPC action; after a network switch
- Exploit idea: skip a required passphrase prompt because prompt reason or route guard becomes stale
- Invariant to test: persisted preferences must not grant authority without current authentication
- Expected Immunefi impact: Critical: secret exposure or signing-context confusion; High: passphrase/profile/auto-login/auth gate bypass
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

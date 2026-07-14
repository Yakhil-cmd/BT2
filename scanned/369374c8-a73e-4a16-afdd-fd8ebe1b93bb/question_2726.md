# Q2726: rpc-state via useSkipMigration 2726

## Question
Can an unprivileged attacker entering through the service command response correlation in `useSkipMigration` (packages/core/src/hooks/useSkipMigration.ts) control large numeric fields near JS precision limits after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useSkipMigration.ts` / `useSkipMigration`
- Entrypoint: service command response correlation
- Attacker controls: large numeric fields near JS precision limits; after a network switch
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

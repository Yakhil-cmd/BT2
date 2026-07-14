# Q795: rpc-state via TransactionTypeFilterMode 795

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `TransactionTypeFilterMode` (packages/api/src/constants/TransactionTypeFilterMode.ts) control large numeric fields near JS precision limits with a cached permission entry and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/constants/TransactionTypeFilterMode.ts` / `TransactionTypeFilterMode`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with a cached permission entry
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

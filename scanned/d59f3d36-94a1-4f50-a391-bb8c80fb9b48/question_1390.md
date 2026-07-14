# Q1390: rpc-state via mojoToCATLocaleString 1390

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `mojoToCATLocaleString` (packages/gui/src/electron/utils/mojoToCATLocaleString.ts) control large numeric fields near JS precision limits with a duplicate identifier and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/mojoToCATLocaleString.ts` / `mojoToCATLocaleString`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; with a duplicate identifier
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

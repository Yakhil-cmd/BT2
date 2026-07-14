# Q2780: rpc-state via if 2780

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `if` (packages/gui/src/util/getPercentPointsSuccessfull.ts) control subscription event for a different wallet/fingerprint with a stale Redux cache and drive the sequence open notification -> resolve details -> execute so the GUI would transform attacker-controlled keys into privileged fields, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/getPercentPointsSuccessfull.ts` / `if`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with a stale Redux cache
- Exploit idea: transform attacker-controlled keys into privileged fields
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

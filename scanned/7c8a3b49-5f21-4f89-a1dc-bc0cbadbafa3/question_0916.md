# Q916: rpc-state via isLocalhost 916

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `isLocalhost` (packages/gui/src/util/isLocalhost.ts) control out-of-order event and query responses with precision-boundary values and drive the sequence import -> parse -> preview -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/isLocalhost.ts` / `isLocalhost`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; with precision-boundary values
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

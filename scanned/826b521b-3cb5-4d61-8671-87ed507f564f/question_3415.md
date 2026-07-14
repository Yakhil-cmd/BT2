# Q3415: rpc-state via index 3415

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `index` (packages/gui/src/electron/components/Collapsible/index.ts) control subscription event for a different wallet/fingerprint with a cached permission entry and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/components/Collapsible/index.ts` / `index`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with a cached permission entry
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict

# Q1351: rpc-state via switch 1351

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `switch` (packages/wallets/src/utils/getWalletPrimaryTitle.ts) control out-of-order event and query responses after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would correlate a command response to the wrong pending request, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/utils/getWalletPrimaryTitle.ts` / `switch`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; after a failed RPC response
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields

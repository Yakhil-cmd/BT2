# Q3810: rpc-state via getWalletInfos 3810

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `getWalletInfos` (packages/gui/src/electron/api/getWalletNames.ts) control subscription event for a different wallet/fingerprint with case-normalized identifiers and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/getWalletNames.ts` / `getWalletInfos`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with case-normalized identifiers
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

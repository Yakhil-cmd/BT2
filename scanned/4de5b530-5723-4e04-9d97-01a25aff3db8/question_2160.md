# Q2160: rpc-state via getNetworkInfo 2160

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `getNetworkInfo` (packages/gui/src/electron/api/getNetworkInfo.ts) control subscription event for a different wallet/fingerprint during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/getNetworkInfo.ts` / `getNetworkInfo`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; during a pending modal confirmation
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

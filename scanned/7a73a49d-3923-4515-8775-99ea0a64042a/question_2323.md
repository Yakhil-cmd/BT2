# Q2323: rpc-state via mojoToCAT 2323

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `mojoToCAT` (packages/gui/src/electron/utils/mojoToCAT.ts) control subscription event for a different wallet/fingerprint with a cached permission entry and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/mojoToCAT.ts` / `mojoToCAT`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with a cached permission entry
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

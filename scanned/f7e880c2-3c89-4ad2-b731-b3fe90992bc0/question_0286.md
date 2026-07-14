# Q286: rpc-state via getKeyDetails 286

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `getKeyDetails` (packages/gui/src/electron/api/getKeyDetails.ts) control subscription event for a different wallet/fingerprint with precision-boundary values and drive the sequence select -> edit backing object -> submit so the GUI would display one balance/asset state while executing with another, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/getKeyDetails.ts` / `getKeyDetails`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; with precision-boundary values
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

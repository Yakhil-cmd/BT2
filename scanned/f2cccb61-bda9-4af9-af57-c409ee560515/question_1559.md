# Q1559: rpc-state via isDisplayableUrl 1559

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `isDisplayableUrl` (packages/gui/src/electron/dialogs/Confirm/Confirm.tsx) control response object with duplicate camelCase/snake_case keys after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/dialogs/Confirm/Confirm.tsx` / `isDisplayableUrl`
- Entrypoint: WebSocket event subscription
- Attacker controls: response object with duplicate camelCase/snake_case keys; after a network switch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

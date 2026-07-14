# Q2792: rpc-state via hexToArray 2792

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `hexToArray` (packages/gui/src/util/utils.js) control response object with duplicate camelCase/snake_case keys after canceling and reopening the dialog and drive the sequence select -> edit backing object -> submit so the GUI would display one balance/asset state while executing with another, violating the invariant that RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/utils.js` / `hexToArray`
- Entrypoint: WebSocket event subscription
- Attacker controls: response object with duplicate camelCase/snake_case keys; after canceling and reopening the dialog
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: RPC/event data must be correlated to the correct request, service, wallet, fingerprint, and numeric precision before driving approvals
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

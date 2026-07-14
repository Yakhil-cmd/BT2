# Q1571: rpc-state via isNumericKey 1571

## Question
Can an unprivileged attacker entering through the RTK query cache update in `isNumericKey` (packages/gui/src/electron/utils/isNumericKey.ts) control response object with duplicate camelCase/snake_case keys after a failed RPC response and drive the sequence connect -> approve -> switch context -> execute so the GUI would correlate a command response to the wrong pending request, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/isNumericKey.ts` / `isNumericKey`
- Entrypoint: RTK query cache update
- Attacker controls: response object with duplicate camelCase/snake_case keys; after a failed RPC response
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

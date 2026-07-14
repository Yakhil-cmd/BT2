# Q3872: rpc-state via normalizePoolState 3872

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `normalizePoolState` (packages/api-react/src/utils/normalizePoolState.ts) control subscription event for a different wallet/fingerprint after a profile switch and drive the sequence open notification -> resolve details -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/utils/normalizePoolState.ts` / `normalizePoolState`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; after a profile switch
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

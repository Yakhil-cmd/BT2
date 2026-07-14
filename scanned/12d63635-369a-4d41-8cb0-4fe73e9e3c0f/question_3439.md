# Q3439: rpc-state via isNumericKey 3439

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `isNumericKey` (packages/gui/src/electron/utils/isNumericKey.ts) control subscription event for a different wallet/fingerprint with precision-boundary values and drive the sequence validate input -> normalize payload -> call RPC so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/utils/isNumericKey.ts` / `isNumericKey`
- Entrypoint: daemon RPC response handling
- Attacker controls: subscription event for a different wallet/fingerprint; with precision-boundary values
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

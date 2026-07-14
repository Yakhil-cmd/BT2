# Q1220: rpc-state via index 1220

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `index` (packages/gui/src/electron/api/getKeyDetails.ts) control out-of-order event and query responses through a batch of rapid user-accessible actions and drive the sequence load persisted state -> render approval -> execute command so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/getKeyDetails.ts` / `index`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; through a batch of rapid user-accessible actions
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

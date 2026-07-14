# Q1997: rpc-state via createUserWallet 1997

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `createUserWallet` (packages/api/src/wallets/RL.ts) control out-of-order event and query responses during a pending modal confirmation and drive the sequence download or render content -> trigger linked wallet action so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/RL.ts` / `createUserWallet`
- Entrypoint: WebSocket event subscription
- Attacker controls: out-of-order event and query responses; during a pending modal confirmation
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

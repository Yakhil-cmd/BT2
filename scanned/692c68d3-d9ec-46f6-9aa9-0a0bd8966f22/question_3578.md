# Q3578: rpc-state via ProofOfSpace 3578

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `ProofOfSpace` (packages/api/src/@types/ProofOfSpace.ts) control large numeric fields near JS precision limits through a batch of rapid user-accessible actions and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/ProofOfSpace.ts` / `ProofOfSpace`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; through a batch of rapid user-accessible actions
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

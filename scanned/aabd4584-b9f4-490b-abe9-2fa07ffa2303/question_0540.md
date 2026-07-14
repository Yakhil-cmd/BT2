# Q540: rpc-state via BlockchainConnection 540

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `BlockchainConnection` (packages/api/src/@types/BlockchainConnection.ts) control large numeric fields near JS precision limits with a stale Redux cache and drive the sequence import -> parse -> preview -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/BlockchainConnection.ts` / `BlockchainConnection`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with a stale Redux cache
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

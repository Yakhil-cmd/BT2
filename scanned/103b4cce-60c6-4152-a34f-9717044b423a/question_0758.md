# Q758: rpc-state via Foliage 758

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `Foliage` (packages/api/src/@types/Foliage.ts) control large numeric fields near JS precision limits with a duplicate identifier and drive the sequence open notification -> resolve details -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/Foliage.ts` / `Foliage`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with a duplicate identifier
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

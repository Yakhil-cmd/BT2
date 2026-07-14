# Q1495: rpc-state via constructor 1495

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `constructor` (packages/api/src/Message.ts) control large numeric fields near JS precision limits after a network switch and drive the sequence open notification -> resolve details -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/Message.ts` / `constructor`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; after a network switch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

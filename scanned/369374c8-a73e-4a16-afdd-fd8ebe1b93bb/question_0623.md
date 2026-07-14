# Q623: rpc-state via WebSocketAPI 623

## Question
Can an unprivileged attacker entering through the service command response correlation in `WebSocketAPI` (packages/gui/src/electron/constants/WebSocketAPI.ts) control large numeric fields near JS precision limits after canceling and reopening the dialog and drive the sequence download or render content -> trigger linked wallet action so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/constants/WebSocketAPI.ts` / `WebSocketAPI`
- Entrypoint: service command response correlation
- Attacker controls: large numeric fields near JS precision limits; after canceling and reopening the dialog
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

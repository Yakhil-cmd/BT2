# Q416: rpc-state via getWalletPrimaryTitle 416

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `getWalletPrimaryTitle` (packages/wallets/src/utils/getWalletPrimaryTitle.ts) control large numeric fields near JS precision limits with hidden Unicode characters and drive the sequence connect -> approve -> switch context -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/utils/getWalletPrimaryTitle.ts` / `getWalletPrimaryTitle`
- Entrypoint: WebSocket event subscription
- Attacker controls: large numeric fields near JS precision limits; with hidden Unicode characters
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

# Q946: rpc-state via createNewPoolWallet 946

## Question
Can an unprivileged attacker entering through the RTK query cache update in `createNewPoolWallet` (packages/api/src/wallets/Pool.ts) control large numeric fields near JS precision limits with a delayed metadata fetch and drive the sequence import -> parse -> preview -> submit so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/Pool.ts` / `createNewPoolWallet`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; with a delayed metadata fetch
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

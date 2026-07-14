# Q1529: rpc-state via index 1529

## Question
Can an unprivileged attacker entering through the service command response correlation in `index` (packages/wallets/src/components/index.ts) control large numeric fields near JS precision limits after a network switch and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/index.ts` / `index`
- Entrypoint: service command response correlation
- Attacker controls: large numeric fields near JS precision limits; after a network switch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

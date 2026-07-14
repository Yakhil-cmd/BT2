# Q3542: rpc-state via dayBefore 3542

## Question
Can an unprivileged attacker entering through the service command response correlation in `dayBefore` (packages/api-react/src/utils/removeOldPoints.ts) control large numeric fields near JS precision limits with a stale Redux cache and drive the sequence import -> parse -> preview -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/utils/removeOldPoints.ts` / `dayBefore`
- Entrypoint: service command response correlation
- Attacker controls: large numeric fields near JS precision limits; with a stale Redux cache
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

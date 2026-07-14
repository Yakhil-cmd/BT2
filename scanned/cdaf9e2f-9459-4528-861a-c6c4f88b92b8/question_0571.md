# Q571: rpc-state via Service 571

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `Service` (packages/api/src/services/Service.ts) control RPC error payload shaped like success with precision-boundary values and drive the sequence preview -> mutate controlled state -> confirm so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/Service.ts` / `Service`
- Entrypoint: WebSocket event subscription
- Attacker controls: RPC error payload shaped like success; with precision-boundary values
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

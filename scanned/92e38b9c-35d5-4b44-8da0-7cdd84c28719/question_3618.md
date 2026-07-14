# Q3618: rpc-state via toSnakeCase 3618

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `toSnakeCase` (packages/api/src/utils/toSnakeCase.ts) control out-of-order event and query responses after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/utils/toSnakeCase.ts` / `toSnakeCase`
- Entrypoint: camel/snake case transform path
- Attacker controls: out-of-order event and query responses; after a failed RPC response
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

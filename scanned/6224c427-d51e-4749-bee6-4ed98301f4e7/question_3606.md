# Q3606: rpc-state via index 3606

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `index` (packages/api/src/services/index.ts) control out-of-order event and query responses with case-normalized identifiers and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/services/index.ts` / `index`
- Entrypoint: camel/snake case transform path
- Attacker controls: out-of-order event and query responses; with case-normalized identifiers
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

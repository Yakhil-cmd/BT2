# Q1784: rpc-state via if 1784

## Question
Can an unprivileged attacker entering through the RTK query cache update in `if` (packages/core/src/hooks/useMode.ts) control out-of-order event and query responses with reordered RPC events and drive the sequence download or render content -> trigger linked wallet action so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useMode.ts` / `if`
- Entrypoint: RTK query cache update
- Attacker controls: out-of-order event and query responses; with reordered RPC events
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

# Q816: rpc-state via toSnakeCase 816

## Question
Can an unprivileged attacker entering through the RTK query cache update in `toSnakeCase` (packages/api/src/utils/toSnakeCase.ts) control RPC error payload shaped like success with a cached permission entry and drive the sequence fetch -> cache -> refresh -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/utils/toSnakeCase.ts` / `toSnakeCase`
- Entrypoint: RTK query cache update
- Attacker controls: RPC error payload shaped like success; with a cached permission entry
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

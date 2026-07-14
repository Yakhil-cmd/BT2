# Q2641: rpc-state via Point 2641

## Question
Can an unprivileged attacker entering through the RTK query cache update in `Point` (packages/api/src/@types/Point.ts) control response object with duplicate camelCase/snake_case keys with a stale Redux cache and drive the sequence load persisted state -> render approval -> execute command so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/Point.ts` / `Point`
- Entrypoint: RTK query cache update
- Attacker controls: response object with duplicate camelCase/snake_case keys; with a stale Redux cache
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload

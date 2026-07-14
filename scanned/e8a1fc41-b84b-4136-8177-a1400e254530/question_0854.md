# Q854: rpc-state via useScrollbarsSettings 854

## Question
Can an unprivileged attacker entering through the RTK query cache update in `useScrollbarsSettings` (packages/core/src/hooks/useScrollbarsSettings.tsx) control response object with duplicate camelCase/snake_case keys with a redirected remote resource and drive the sequence validate input -> normalize payload -> call RPC so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useScrollbarsSettings.tsx` / `useScrollbarsSettings`
- Entrypoint: RTK query cache update
- Attacker controls: response object with duplicate camelCase/snake_case keys; with a redirected remote resource
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action

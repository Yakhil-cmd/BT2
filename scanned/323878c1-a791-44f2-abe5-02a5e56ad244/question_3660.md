# Q3660: rpc-state via useSkipMigration 3660

## Question
Can an unprivileged attacker entering through the RTK query cache update in `useSkipMigration` (packages/core/src/hooks/useSkipMigration.ts) control response object with duplicate camelCase/snake_case keys with precision-boundary values and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useSkipMigration.ts` / `useSkipMigration`
- Entrypoint: RTK query cache update
- Attacker controls: response object with duplicate camelCase/snake_case keys; with precision-boundary values
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

# Q2724: rpc-state via useShowDebugInformation 2724

## Question
Can an unprivileged attacker entering through the service command response correlation in `useShowDebugInformation` (packages/core/src/hooks/useShowDebugInformation.ts) control response object with duplicate camelCase/snake_case keys with case-normalized identifiers and drive the sequence connect -> approve -> switch context -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useShowDebugInformation.ts` / `useShowDebugInformation`
- Entrypoint: service command response correlation
- Attacker controls: response object with duplicate camelCase/snake_case keys; with case-normalized identifiers
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

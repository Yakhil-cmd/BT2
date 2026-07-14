# Q814: rpc-state via toCamelCase 814

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `toCamelCase` (packages/api/src/utils/toCamelCase.ts) control RPC error payload shaped like success with a redirected remote resource and drive the sequence fetch -> cache -> refresh -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/utils/toCamelCase.ts` / `toCamelCase`
- Entrypoint: daemon RPC response handling
- Attacker controls: RPC error payload shaped like success; with a redirected remote resource
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

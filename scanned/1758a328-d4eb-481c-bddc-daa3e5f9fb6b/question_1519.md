# Q1519: rpc-state via SignMessageEntities 1519

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `SignMessageEntities` (packages/gui/src/components/signVerify/SignMessageEntities.ts) control response object with duplicate camelCase/snake_case keys with precision-boundary values and drive the sequence open notification -> resolve details -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/components/signVerify/SignMessageEntities.ts` / `SignMessageEntities`
- Entrypoint: camel/snake case transform path
- Attacker controls: response object with duplicate camelCase/snake_case keys; with precision-boundary values
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match

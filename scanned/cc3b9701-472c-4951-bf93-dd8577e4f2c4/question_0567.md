# Q567: rpc-state via ServiceName 567

## Question
Can an unprivileged attacker entering through the RTK query cache update in `ServiceName` (packages/api/src/constants/ServiceName.ts) control large numeric fields near JS precision limits through a batch of rapid user-accessible actions and drive the sequence select -> edit backing object -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/constants/ServiceName.ts` / `ServiceName`
- Entrypoint: RTK query cache update
- Attacker controls: large numeric fields near JS precision limits; through a batch of rapid user-accessible actions
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

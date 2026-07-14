# Q3652: rpc-state via if 3652

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `if` (packages/core/src/hooks/useMode.ts) control large numeric fields near JS precision limits after a failed RPC response and drive the sequence connect -> approve -> switch context -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useMode.ts` / `if`
- Entrypoint: daemon RPC response handling
- Attacker controls: large numeric fields near JS precision limits; after a failed RPC response
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

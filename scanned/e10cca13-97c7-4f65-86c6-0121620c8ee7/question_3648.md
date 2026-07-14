# Q3648: rpc-state via setIsNFTMultipleHide 3648

## Question
Can an unprivileged attacker entering through the RTK query cache update in `setIsNFTMultipleHide` (packages/core/src/hooks/useHiddenList.ts) control response object with duplicate camelCase/snake_case keys during a pending modal confirmation and drive the sequence preview -> mutate controlled state -> confirm so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useHiddenList.ts` / `setIsNFTMultipleHide`
- Entrypoint: RTK query cache update
- Attacker controls: response object with duplicate camelCase/snake_case keys; during a pending modal confirmation
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

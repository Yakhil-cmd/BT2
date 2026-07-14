# Q2785: rpc-state via isRankingAttribute 2785

## Question
Can an unprivileged attacker entering through the RTK query cache update in `isRankingAttribute` (packages/gui/src/util/isRankingAttribute.ts) control out-of-order event and query responses with hidden Unicode characters and drive the sequence connect -> approve -> switch context -> execute so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/isRankingAttribute.ts` / `isRankingAttribute`
- Entrypoint: RTK query cache update
- Attacker controls: out-of-order event and query responses; with hidden Unicode characters
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

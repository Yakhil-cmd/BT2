# Q2728: rpc-state via to 2728

## Question
Can an unprivileged attacker entering through the RTK query cache update in `to` (packages/core/src/utils/chiaFormatter.ts) control out-of-order event and query responses with a cached permission entry and drive the sequence import -> parse -> preview -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/utils/chiaFormatter.ts` / `to`
- Entrypoint: RTK query cache update
- Attacker controls: out-of-order event and query responses; with a cached permission entry
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

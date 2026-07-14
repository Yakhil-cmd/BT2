# Q2626: rpc-state via Foliage 2626

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `Foliage` (packages/api/src/@types/Foliage.ts) control RPC error payload shaped like success with a stale Redux cache and drive the sequence load persisted state -> render approval -> execute command so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/Foliage.ts` / `Foliage`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; with a stale Redux cache
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

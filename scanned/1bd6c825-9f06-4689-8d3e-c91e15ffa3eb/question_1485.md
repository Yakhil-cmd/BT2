# Q1485: rpc-state via PoolInfo 1485

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `PoolInfo` (packages/api/src/@types/PoolInfo.ts) control RPC error payload shaped like success with case-normalized identifiers and drive the sequence connect -> approve -> switch context -> execute so the GUI would correlate a command response to the wrong pending request, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/PoolInfo.ts` / `PoolInfo`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; with case-normalized identifiers
- Exploit idea: correlate a command response to the wrong pending request
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value

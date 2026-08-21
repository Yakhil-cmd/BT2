# Q275: hash collision surface in hash::expecting

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling inputs whose concatenation before hashing is ambiguous, drive `core/primitives-core/src/hash.rs::expecting` to collide two distinct logical inputs under one hash, breaking the invariant that hash preimages are unambiguously delimited, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `core/primitives-core/src/hash.rs` -> `expecting`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: inputs whose concatenation before hashing is ambiguous
- Exploit idea: collide two distinct logical inputs under one hash
- Invariant to test: hash preimages are unambiguously delimited
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case

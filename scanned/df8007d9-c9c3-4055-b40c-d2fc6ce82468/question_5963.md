# Q5963: CheckNonce type confusion in raw transaction decoding

## Question
Can an unprivileged attacker reach `CheckNonce` through raw transaction bytes decoded into executable transaction structs using nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes and make `CheckNonce` decode one intent for validation but another for execution, causing the invariant that the transaction bytes accepted for validation must be identical to the bytes interpreted for execution and hashing to fail and leading to Transaction manipulation?

## Target
- File/function: blockchain/types/transaction.go:469 (CheckNonce)
- Entrypoint: raw transaction bytes decoded into executable transaction structs
- Attacker controls: nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes
- Exploit idea: make `CheckNonce` decode one intent for validation but another for execution
- Invariant to test: the transaction bytes accepted for validation must be identical to the bytes interpreted for execution and hashing
- Expected Immunefi impact: Transaction manipulation
- Fast validation: feed paired raw encodings that should be equivalent and assert hash, signer, and executed fields cannot diverge

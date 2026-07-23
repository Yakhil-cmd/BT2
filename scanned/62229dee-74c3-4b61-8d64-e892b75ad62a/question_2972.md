# Q2972: removeTx type confusion in raw transaction decoding

## Question
Can an unprivileged attacker reach `removeTx` through raw transaction bytes decoded into executable transaction structs using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and make `removeTx` decode one intent for validation but another for execution, causing the invariant that the transaction bytes accepted for validation must be identical to the bytes interpreted for execution and hashing to fail and leading to Transaction manipulation?

## Target
- File/function: blockchain/tx_pool.go:1656 (removeTx)
- Entrypoint: raw transaction bytes decoded into executable transaction structs
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: make `removeTx` decode one intent for validation but another for execution
- Invariant to test: the transaction bytes accepted for validation must be identical to the bytes interpreted for execution and hashing
- Expected Immunefi impact: Transaction manipulation
- Fast validation: feed paired raw encodings that should be equivalent and assert hash, signer, and executed fields cannot diverge

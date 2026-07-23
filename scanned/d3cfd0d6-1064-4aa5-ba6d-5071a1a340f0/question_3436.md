# Q3436: PopTxs type confusion in raw transaction decoding

## Question
Can an unprivileged attacker reach `PopTxs` through raw transaction bytes decoded into executable transaction structs using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and make `PopTxs` decode one intent for validation but another for execution, causing the invariant that the transaction bytes accepted for validation must be identical to the bytes interpreted for execution and hashing to fail and leading to Transaction manipulation?

## Target
- File/function: work/builder/builder.go:197 (PopTxs)
- Entrypoint: raw transaction bytes decoded into executable transaction structs
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: make `PopTxs` decode one intent for validation but another for execution
- Invariant to test: the transaction bytes accepted for validation must be identical to the bytes interpreted for execution and hashing
- Expected Immunefi impact: Transaction manipulation
- Fast validation: feed paired raw encodings that should be equivalent and assert hash, signer, and executed fields cannot diverge

# Q4294: Verify hash-domain confusion

## Question
Can an unprivileged attacker reach `Verify` through message hashing before signature verification or typed-data binding using signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings and make `Verify` hash one message for signing but a different message for verification, causing the invariant that signed message bytes and verified message bytes must match exactly under one domain rule to fail and leading to Unauthorized transaction?

## Target
- File/function: crypto/secp256r1/verifier.go:27 (Verify)
- Entrypoint: message hashing before signature verification or typed-data binding
- Attacker controls: signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings
- Exploit idea: make `Verify` hash one message for signing but a different message for verification
- Invariant to test: signed message bytes and verified message bytes must match exactly under one domain rule
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: sign under one domain or prefix and try verifying under another and assert no cross-domain acceptance is possible

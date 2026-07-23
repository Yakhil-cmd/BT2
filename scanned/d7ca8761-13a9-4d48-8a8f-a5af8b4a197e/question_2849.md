# Q2849: Verify malleability or zero-value acceptance

## Question
Can an unprivileged attacker reach `Verify` through signature validation or recovery path using signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings and make `Verify` accept multiple distinct encodings for the same authorization or an authorization that should be impossible, causing the invariant that invalid or non-canonical encodings must be rejected before any stateful caller can trust them to fail and leading to Cryptographic flaws?

## Target
- File/function: crypto/secp256r1/verifier.go:27 (Verify)
- Entrypoint: signature validation or recovery path
- Attacker controls: signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings
- Exploit idea: make `Verify` accept multiple distinct encodings for the same authorization or an authorization that should be impossible
- Invariant to test: invalid or non-canonical encodings must be rejected before any stateful caller can trust them
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: fuzz edge-case signature components and assert no invalid encoding reaches an accepted signer

# Q2850: Ecrecover malleability or zero-value acceptance

## Question
Can an unprivileged attacker reach `Ecrecover` through signature validation or recovery path using signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings and make `Ecrecover` accept multiple distinct encodings for the same authorization or an authorization that should be impossible, causing the invariant that invalid or non-canonical encodings must be rejected before any stateful caller can trust them to fail and leading to Cryptographic flaws?

## Target
- File/function: crypto/signature_cgo.go:37 (Ecrecover)
- Entrypoint: signature validation or recovery path
- Attacker controls: signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings
- Exploit idea: make `Ecrecover` accept multiple distinct encodings for the same authorization or an authorization that should be impossible
- Invariant to test: invalid or non-canonical encodings must be rejected before any stateful caller can trust them
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: fuzz edge-case signature components and assert no invalid encoding reaches an accepted signer

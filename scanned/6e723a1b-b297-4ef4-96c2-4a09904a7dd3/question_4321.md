# Q4321: makeSimplePtrDecoder malleability or zero-value acceptance

## Question
Can an unprivileged attacker reach `makeSimplePtrDecoder` through signature validation or recovery path using non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings and make `makeSimplePtrDecoder` accept multiple distinct encodings for the same authorization or an authorization that should be impossible, causing the invariant that invalid or non-canonical encodings must be rejected before any stateful caller can trust them to fail and leading to Cryptographic flaws?

## Target
- File/function: rlp/decode.go:462 (makeSimplePtrDecoder)
- Entrypoint: signature validation or recovery path
- Attacker controls: non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings
- Exploit idea: make `makeSimplePtrDecoder` accept multiple distinct encodings for the same authorization or an authorization that should be impossible
- Invariant to test: invalid or non-canonical encodings must be rejected before any stateful caller can trust them
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: fuzz edge-case signature components and assert no invalid encoding reaches an accepted signer

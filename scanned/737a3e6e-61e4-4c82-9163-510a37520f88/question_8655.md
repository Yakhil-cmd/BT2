# Q8655: makePtrDecoder public-key acceptance gap

## Question
Can an unprivileged attacker reach `makePtrDecoder` through public-key or secret-key byte import used for verification contexts using non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings and make `makePtrDecoder` import key material that should be invalid yet later authorizes signatures, causing the invariant that key import must reject any material that can destabilize later verification guarantees to fail and leading to Cryptographic flaws?

## Target
- File/function: rlp/decode.go:449 (makePtrDecoder)
- Entrypoint: public-key or secret-key byte import used for verification contexts
- Attacker controls: non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings
- Exploit idea: make `makePtrDecoder` import key material that should be invalid yet later authorizes signatures
- Invariant to test: key import must reject any material that can destabilize later verification guarantees
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: import malformed keys into validation paths and assert no accepted key can later pass verification unexpectedly

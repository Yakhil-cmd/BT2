# Q1337: MultiplePublicKeysFromBytes public-key acceptance gap

## Question
Can an unprivileged attacker reach `MultiplePublicKeysFromBytes` through public-key or secret-key byte import used for verification contexts using signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings and make `MultiplePublicKeysFromBytes` import key material that should be invalid yet later authorizes signatures, causing the invariant that key import must reject any material that can destabilize later verification guarantees to fail and leading to Cryptographic flaws?

## Target
- File/function: crypto/bls/bls.go:126 (MultiplePublicKeysFromBytes)
- Entrypoint: public-key or secret-key byte import used for verification contexts
- Attacker controls: signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings
- Exploit idea: make `MultiplePublicKeysFromBytes` import key material that should be invalid yet later authorizes signatures
- Invariant to test: key import must reject any material that can destabilize later verification guarantees
- Expected Immunefi impact: Cryptographic flaws
- Fast validation: import malformed keys into validation paths and assert no accepted key can later pass verification unexpectedly

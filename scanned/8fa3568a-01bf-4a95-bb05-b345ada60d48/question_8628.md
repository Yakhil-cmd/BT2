# Q8628: checkSignature RLP differential decode

## Question
Can an unprivileged attacker reach `checkSignature` through RLP stream or raw-value decoding of network or transaction payloads using signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings and make `checkSignature` decode the same raw bytes into different semantic values in different callers, causing the invariant that every accepted RLP byte string must decode to one canonical semantic object everywhere it is used to fail and leading to Transaction manipulation?

## Target
- File/function: crypto/secp256k1/secp256.go:62 (checkSignature)
- Entrypoint: RLP stream or raw-value decoding of network or transaction payloads
- Attacker controls: signature bytes, public-key bytes, message hashes, proof bytes, and alternate encodings
- Exploit idea: make `checkSignature` decode the same raw bytes into different semantic values in different callers
- Invariant to test: every accepted RLP byte string must decode to one canonical semantic object everywhere it is used
- Expected Immunefi impact: Transaction manipulation
- Fast validation: replay the same crafted RLP payload through all callers and assert signer, hash, and semantic fields stay identical

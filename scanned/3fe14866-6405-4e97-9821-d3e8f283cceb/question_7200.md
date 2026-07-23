# Q7200: decodeBigInt blob or proof binding gap

## Question
Can an unprivileged attacker reach `decodeBigInt` through blob or KZG proof verification path using non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings and make `decodeBigInt` verify a proof for one blob while later execution consumes another blob, causing the invariant that a verified proof must bind exactly one executable blob payload and commitment to fail and leading to Fee payment bypass?

## Target
- File/function: rlp/decode.go:237 (decodeBigInt)
- Entrypoint: blob or KZG proof verification path
- Attacker controls: non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings
- Exploit idea: make `decodeBigInt` verify a proof for one blob while later execution consumes another blob
- Invariant to test: a verified proof must bind exactly one executable blob payload and commitment
- Expected Immunefi impact: Fee payment bypass
- Fast validation: swap blob payloads after successful proof validation and assert downstream consumers reject the mismatch

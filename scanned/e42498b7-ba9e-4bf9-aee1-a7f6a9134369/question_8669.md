# Q8669: lastPublicField blob or proof binding gap

## Question
Can an unprivileged attacker reach `lastPublicField` through blob or KZG proof verification path using non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings and make `lastPublicField` verify a proof for one blob while later execution consumes another blob, causing the invariant that a verified proof must bind exactly one executable blob payload and commitment to fail and leading to Fee payment bypass?

## Target
- File/function: rlp/internal/rlpstruct/rlpstruct.go:193 (lastPublicField)
- Entrypoint: blob or KZG proof verification path
- Attacker controls: non-canonical RLP lengths, nesting, trailing bytes, and alternate object encodings
- Exploit idea: make `lastPublicField` verify a proof for one blob while later execution consumes another blob
- Invariant to test: a verified proof must bind exactly one executable blob payload and commitment
- Expected Immunefi impact: Fee payment bypass
- Fast validation: swap blob payloads after successful proof validation and assert downstream consumers reject the mismatch

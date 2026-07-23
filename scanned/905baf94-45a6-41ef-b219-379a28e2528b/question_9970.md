# Q9970: validateBidSigs builder-side decode differential

## Question
Can an unprivileged attacker reach `validateBidSigs` through RLP or typed-data decode path before execution using signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing and make `validateBidSigs` validate one decoded bid but execute another, causing the invariant that decoded bid fields must be canonical and stable across validation and execution to fail and leading to Transaction manipulation?

## Target
- File/function: kaiax/auction/impl/bid_pool.go:393 (validateBidSigs)
- Entrypoint: RLP or typed-data decode path before execution
- Attacker controls: signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing
- Exploit idea: make `validateBidSigs` validate one decoded bid but execute another
- Invariant to test: decoded bid fields must be canonical and stable across validation and execution
- Expected Immunefi impact: Transaction manipulation
- Fast validation: fuzz bid encoding boundaries and assert decoded fields, signer, and executed tx remain identical

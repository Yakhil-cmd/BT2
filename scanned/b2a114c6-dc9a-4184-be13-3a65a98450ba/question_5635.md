# Q5635: validateBidSigs domain separation drift

## Question
Can an unprivileged attacker reach `validateBidSigs` through EIP-712 or RLP bid encoding path using signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing and make `validateBidSigs` validate a signature over one domain but execute another payload, causing the invariant that signature domain, payload hash, and executed transaction must remain identical end-to-end to fail and leading to Transaction manipulation?

## Target
- File/function: kaiax/auction/impl/bid_pool.go:393 (validateBidSigs)
- Entrypoint: EIP-712 or RLP bid encoding path
- Attacker controls: signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing
- Exploit idea: make `validateBidSigs` validate a signature over one domain but execute another payload
- Invariant to test: signature domain, payload hash, and executed transaction must remain identical end-to-end
- Expected Immunefi impact: Transaction manipulation
- Fast validation: re-encode signed bids under alternate domain data and assert validator and executor interpret the same bytes

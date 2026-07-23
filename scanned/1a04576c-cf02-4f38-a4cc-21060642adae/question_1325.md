# Q1325: decodeSwapTx domain separation drift

## Question
Can an unprivileged attacker reach `decodeSwapTx` through EIP-712 or RLP bid encoding path using signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing and make `decodeSwapTx` validate a signature over one domain but execute another payload, causing the invariant that signature domain, payload hash, and executed transaction must remain identical end-to-end to fail and leading to Transaction manipulation?

## Target
- File/function: kaiax/gasless/impl/getter.go:142 (decodeSwapTx)
- Entrypoint: EIP-712 or RLP bid encoding path
- Attacker controls: signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing
- Exploit idea: make `decodeSwapTx` validate a signature over one domain but execute another payload
- Invariant to test: signature domain, payload hash, and executed transaction must remain identical end-to-end
- Expected Immunefi impact: Transaction manipulation
- Fast validation: re-encode signed bids under alternate domain data and assert validator and executor interpret the same bytes

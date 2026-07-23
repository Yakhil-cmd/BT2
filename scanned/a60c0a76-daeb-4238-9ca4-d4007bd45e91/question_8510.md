# Q8510: EncodeRLP searcher or auctioneer signature confusion

## Question
Can an unprivileged attacker reach `EncodeRLP` through bid validation path using signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing and make `EncodeRLP` accept one role’s signature as satisfying the other role, causing the invariant that searcher and auctioneer authorizations must be non-interchangeable for the same payload to fail and leading to Unauthorized transaction?

## Target
- File/function: kaiax/auction/bid.go:57 (EncodeRLP)
- Entrypoint: bid validation path
- Attacker controls: signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing
- Exploit idea: make `EncodeRLP` accept one role’s signature as satisfying the other role
- Invariant to test: searcher and auctioneer authorizations must be non-interchangeable for the same payload
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: swap role signatures over the same payload and assert validation never treats them as equivalent

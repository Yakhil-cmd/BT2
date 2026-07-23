# Q2741: AddBid sponsor authorization replay

## Question
Can an unprivileged attacker reach `AddBid` through gasless or auction submission path using signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing and make `AddBid` consume one signature for multiple state-changing executions, causing the invariant that every sponsor or bidder signature must authorize exactly one canonical payload and counter to fail and leading to Unauthorized transaction?

## Target
- File/function: kaiax/auction/impl/bid_pool.go:248 (AddBid)
- Entrypoint: gasless or auction submission path
- Attacker controls: signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing
- Exploit idea: make `AddBid` consume one signature for multiple state-changing executions
- Invariant to test: every sponsor or bidder signature must authorize exactly one canonical payload and counter
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: replay one signed payload under altered ordering and assert no second execution is accepted

# Q5631: AddBid fee extraction bypass

## Question
Can an unprivileged attacker reach `AddBid` through gasless or auction execution accounting using signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing and make `AddBid` settle execution while charging less than the intended sponsor or bid fee, causing the invariant that the paid fee must exactly match the accepted bid or sponsor agreement to fail and leading to Fee payment bypass?

## Target
- File/function: kaiax/auction/impl/bid_pool.go:248 (AddBid)
- Entrypoint: gasless or auction execution accounting
- Attacker controls: signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing
- Exploit idea: make `AddBid` settle execution while charging less than the intended sponsor or bid fee
- Invariant to test: the paid fee must exactly match the accepted bid or sponsor agreement
- Expected Immunefi impact: Fee payment bypass
- Fast validation: submit edge-case fee values and compare charged sponsor or bidder balances against accepted economic terms

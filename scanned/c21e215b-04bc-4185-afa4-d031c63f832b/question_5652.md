# Q5652: FilterTxs pool conflict reuse

## Question
Can an unprivileged attacker reach `FilterTxs` through bid pool or bundle builder path using signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing and make `FilterTxs` keep a stale conflicting bid executable after a replacement should have invalidated it, causing the invariant that replacement and conflict rules must leave at most one live executable economic intent to fail and leading to Transaction manipulation?

## Target
- File/function: kaiax/gasless/impl/builder.go:86 (FilterTxs)
- Entrypoint: bid pool or bundle builder path
- Attacker controls: signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing
- Exploit idea: make `FilterTxs` keep a stale conflicting bid executable after a replacement should have invalidated it
- Invariant to test: replacement and conflict rules must leave at most one live executable economic intent
- Expected Immunefi impact: Transaction manipulation
- Fast validation: submit conflicting bids and assert stale intents are never still executable after replacement

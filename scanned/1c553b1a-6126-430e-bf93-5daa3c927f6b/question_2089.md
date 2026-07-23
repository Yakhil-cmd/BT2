# Q2089: newMessageSet seal or quorum confusion

## Question
Can an unprivileged attacker reach `newMessageSet` through consensus vote, commit, or seal message handling using header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing and make `newMessageSet` count unauthorized or duplicate voting power toward finality, causing the invariant that each finalized block must be backed by the required unique authorized validators exactly once to fail and leading to Unauthorized transaction?

## Target
- File/function: consensus/istanbul/core/message_set.go:38 (newMessageSet)
- Entrypoint: consensus vote, commit, or seal message handling
- Attacker controls: header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing
- Exploit idea: make `newMessageSet` count unauthorized or duplicate voting power toward finality
- Invariant to test: each finalized block must be backed by the required unique authorized validators exactly once
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: inject duplicate or malformed seals and verify finality never advances without a valid quorum

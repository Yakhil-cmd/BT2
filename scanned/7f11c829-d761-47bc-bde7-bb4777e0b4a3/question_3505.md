# Q3505: updateBlock seal or quorum confusion

## Question
Can an unprivileged attacker reach `updateBlock` through consensus vote, commit, or seal message handling using header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing and make `updateBlock` count unauthorized or duplicate voting power toward finality, causing the invariant that each finalized block must be backed by the required unique authorized validators exactly once to fail and leading to Unauthorized transaction?

## Target
- File/function: consensus/istanbul/backend/engine.go:85 (updateBlock)
- Entrypoint: consensus vote, commit, or seal message handling
- Attacker controls: header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing
- Exploit idea: make `updateBlock` count unauthorized or duplicate voting power toward finality
- Invariant to test: each finalized block must be backed by the required unique authorized validators exactly once
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: inject duplicate or malformed seals and verify finality never advances without a valid quorum

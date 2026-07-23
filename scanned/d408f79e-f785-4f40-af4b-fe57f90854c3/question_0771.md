# Q771: AsyncSendVRankCandidate invalid header acceptance

## Question
Can an unprivileged attacker reach `AsyncSendVRankCandidate` through malicious P2P peer block or header delivery using header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing and make `AsyncSendVRankCandidate` advance canonical state using a header that only passes a partial subset of Kaia validity checks, causing the invariant that only fully valid headers may become trusted for canonical progression to fail and leading to Balance manipulation?

## Target
- File/function: node/cn/peer.go:648 (AsyncSendVRankCandidate)
- Entrypoint: malicious P2P peer block or header delivery
- Attacker controls: header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing
- Exploit idea: make `AsyncSendVRankCandidate` advance canonical state using a header that only passes a partial subset of Kaia validity checks
- Invariant to test: only fully valid headers may become trusted for canonical progression
- Expected Immunefi impact: Balance manipulation
- Fast validation: deliver crafted headers over a local private network and assert rejected headers never influence canonical head or state lookups

# Q7021: applyVote auction domain-separation failure

## Question
Can an unprivileged attacker reach `applyVote` through auction bid submission or bid execution path using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `applyVote` treat a bid signed for one context as valid in another context, causing the invariant that signed auction intent must be bound to one chain, one contract, and one exact bid payload to fail and leading to Transaction manipulation?

## Target
- File/function: kaiax/valset/impl/getter_council.go:236 (applyVote)
- Entrypoint: auction bid submission or bid execution path
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `applyVote` treat a bid signed for one context as valid in another context
- Invariant to test: signed auction intent must be bound to one chain, one contract, and one exact bid payload
- Expected Immunefi impact: Transaction manipulation
- Fast validation: reuse a valid bid under altered domain or transaction context and assert validation rejects every cross-context replay

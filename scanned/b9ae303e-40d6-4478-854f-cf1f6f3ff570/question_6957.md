# Q6957: RemoveGovAfter auction domain-separation failure

## Question
Can an unprivileged attacker reach `RemoveGovAfter` through auction bid submission or bid execution path using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `RemoveGovAfter` treat a bid signed for one context as valid in another context, causing the invariant that signed auction intent must be bound to one chain, one contract, and one exact bid payload to fail and leading to Transaction manipulation?

## Target
- File/function: kaiax/gov/headergov/impl/rewind.go:41 (RemoveGovAfter)
- Entrypoint: auction bid submission or bid execution path
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `RemoveGovAfter` treat a bid signed for one context as valid in another context
- Invariant to test: signed auction intent must be bound to one chain, one contract, and one exact bid payload
- Expected Immunefi impact: Transaction manipulation
- Fast validation: reuse a valid bid under altered domain or transaction context and assert validation rejects every cross-context replay

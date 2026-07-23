# Q7051: PrepareHeader auction domain-separation failure

## Question
Can an unprivileged attacker reach `PrepareHeader` through auction bid submission or bid execution path using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `PrepareHeader` treat a bid signed for one context as valid in another context, causing the invariant that signed auction intent must be bound to one chain, one contract, and one exact bid payload to fail and leading to Transaction manipulation?

## Target
- File/function: kaiax/vrank/impl/consensus.go:78 (PrepareHeader)
- Entrypoint: auction bid submission or bid execution path
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `PrepareHeader` treat a bid signed for one context as valid in another context
- Invariant to test: signed auction intent must be bound to one chain, one contract, and one exact bid payload
- Expected Immunefi impact: Transaction manipulation
- Fast validation: reuse a valid bid under altered domain or transaction context and assert validation rejects every cross-context replay

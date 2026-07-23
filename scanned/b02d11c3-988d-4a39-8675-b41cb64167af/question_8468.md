# Q8468: collectStakingAmounts builder conflict leak

## Question
Can an unprivileged attacker reach `collectStakingAmounts` through bundle builder or auction pool ordering path using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `collectStakingAmounts` admit mutually incompatible execution plans that later violate nonce or balance assumptions, causing the invariant that bundle admission must preserve execution exclusivity for conflicting user intents to fail and leading to Transaction manipulation?

## Target
- File/function: kaiax/valset/impl/getter_demote.go:125 (collectStakingAmounts)
- Entrypoint: bundle builder or auction pool ordering path
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `collectStakingAmounts` admit mutually incompatible execution plans that later violate nonce or balance assumptions
- Invariant to test: bundle admission must preserve execution exclusivity for conflicting user intents
- Expected Immunefi impact: Transaction manipulation
- Fast validation: submit conflicting bundles and assert only a state-consistent bundle set can reach execution

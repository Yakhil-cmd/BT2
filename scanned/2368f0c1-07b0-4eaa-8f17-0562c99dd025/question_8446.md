# Q8446: totalSupplyFromState builder conflict leak

## Question
Can an unprivileged attacker reach `totalSupplyFromState` through bundle builder or auction pool ordering path using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `totalSupplyFromState` admit mutually incompatible execution plans that later violate nonce or balance assumptions, causing the invariant that bundle admission must preserve execution exclusivity for conflicting user intents to fail and leading to Transaction manipulation?

## Target
- File/function: kaiax/supply/impl/getter.go:85 (totalSupplyFromState)
- Entrypoint: bundle builder or auction pool ordering path
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `totalSupplyFromState` admit mutually incompatible execution plans that later violate nonce or balance assumptions
- Invariant to test: bundle admission must preserve execution exclusivity for conflicting user intents
- Expected Immunefi impact: Transaction manipulation
- Fast validation: submit conflicting bundles and assert only a state-consistent bundle set can reach execution

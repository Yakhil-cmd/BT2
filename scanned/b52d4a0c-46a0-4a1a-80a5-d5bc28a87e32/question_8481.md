# Q8481: writeLowestScannedVoteNum builder conflict leak

## Question
Can an unprivileged attacker reach `writeLowestScannedVoteNum` through bundle builder or auction pool ordering path using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `writeLowestScannedVoteNum` admit mutually incompatible execution plans that later violate nonce or balance assumptions, causing the invariant that bundle admission must preserve execution exclusivity for conflicting user intents to fail and leading to Transaction manipulation?

## Target
- File/function: kaiax/valset/impl/schema.go:144 (writeLowestScannedVoteNum)
- Entrypoint: bundle builder or auction pool ordering path
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `writeLowestScannedVoteNum` admit mutually incompatible execution plans that later violate nonce or balance assumptions
- Invariant to test: bundle admission must preserve execution exclusivity for conflicting user intents
- Expected Immunefi impact: Transaction manipulation
- Fast validation: submit conflicting bundles and assert only a state-consistent bundle set can reach execution

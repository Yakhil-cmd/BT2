# Q1243: collectStakingAmounts validator-set drift

## Question
Can an unprivileged attacker reach `collectStakingAmounts` through header-gov, valset, or staking transition path using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `collectStakingAmounts` derive a validator set different from the one implied by the accepted chain state, causing the invariant that validator membership and voting power must be a deterministic function of the accepted state and header inputs to fail and leading to Unauthorized transaction?

## Target
- File/function: kaiax/valset/impl/getter_demote.go:125 (collectStakingAmounts)
- Entrypoint: header-gov, valset, or staking transition path
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `collectStakingAmounts` derive a validator set different from the one implied by the accepted chain state
- Invariant to test: validator membership and voting power must be a deterministic function of the accepted state and header inputs
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: feed conflicting staking and header contexts and assert the next validator set cannot diverge between modules

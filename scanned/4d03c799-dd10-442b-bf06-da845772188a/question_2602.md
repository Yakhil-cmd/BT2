# Q2602: VoteBlockNums reward or supply accounting split

## Question
Can an unprivileged attacker reach `VoteBlockNums` through system-transition execution that distributes rewards or mutates total supply using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `VoteBlockNums` credit balances and total supply inconsistently, causing the invariant that reward recipients, burned amounts, and total supply must reconcile exactly after each transition to fail and leading to Violation of tokenomics?

## Target
- File/function: kaiax/gov/headergov/impl/getter.go:50 (VoteBlockNums)
- Entrypoint: system-transition execution that distributes rewards or mutates total supply
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `VoteBlockNums` credit balances and total supply inconsistently
- Invariant to test: reward recipients, burned amounts, and total supply must reconcile exactly after each transition
- Expected Immunefi impact: Violation of tokenomics
- Fast validation: execute a crafted transition and reconcile every reward delta against the post-transition supply accounting

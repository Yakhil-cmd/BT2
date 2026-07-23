# Q2686: applyVote reward or supply accounting split

## Question
Can an unprivileged attacker reach `applyVote` through system-transition execution that distributes rewards or mutates total supply using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `applyVote` credit balances and total supply inconsistently, causing the invariant that reward recipients, burned amounts, and total supply must reconcile exactly after each transition to fail and leading to Violation of tokenomics?

## Target
- File/function: kaiax/valset/impl/getter_council.go:236 (applyVote)
- Entrypoint: system-transition execution that distributes rewards or mutates total supply
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `applyVote` credit balances and total supply inconsistently
- Invariant to test: reward recipients, burned amounts, and total supply must reconcile exactly after each transition
- Expected Immunefi impact: Violation of tokenomics
- Fast validation: execute a crafted transition and reconcile every reward delta against the post-transition supply accounting

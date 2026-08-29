# Q2996: iter-find-superset via borrow: prime shared state so the next caller in the block is eval

## Question
Does `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) let an unprivileged attacker who controls the future mask produced by the new debt bit reach `iter-find-superset` (mainnet/contracts/registry/v0-egroup.clar:267) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it short-circuits on the first superset match, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:267` -> `iter-find-superset`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: the future mask produced by the new debt bit
- Exploit idea: `iter-find-superset` short-circuits on the first superset match. Reach it through `borrow` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `borrow` twice with the future mask produced by the new debt bit varied, and assert that the value `iter-find-superset` returns is identical in both runs; a divergence confirms the finding.

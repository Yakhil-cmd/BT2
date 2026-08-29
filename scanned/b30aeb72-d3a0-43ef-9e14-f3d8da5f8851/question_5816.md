# Q5816: resolve-or-create via collateral-add: prime shared state so the next caller in the block is eval

## Question
Does `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020) let an unprivileged attacker who controls the `ft` trait principal reach `resolve-or-create` (mainnet/contracts/market/v0-market-vault.clar:143) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it allocates a user id through `increment` for whatever principal the market names, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:143` -> `resolve-or-create`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `resolve-or-create` allocates a user id through `increment` for whatever principal the market names. Reach it through `collateral-add` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `collateral-add` twice with the `ft` trait principal varied, and assert that the value `resolve-or-create` returns is identical in both runs; a divergence confirms the finding.

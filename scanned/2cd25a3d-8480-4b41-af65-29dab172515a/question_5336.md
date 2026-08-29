# Q5336: price-multi-resolve via borrow: make a victim's position resolve to a worse efficiency gro

## Question
Does `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) let an unprivileged attacker who controls `amount` reach `price-multi-resolve` (mainnet/contracts/market/v0-4-market.clar:397) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it folds `iter-price-multi` into a POSITIONAL price list, asserting only the `valid` flag at the end, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:397` -> `price-multi-resolve`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `price-multi-resolve` folds `iter-price-multi` into a POSITIONAL price list, asserting only the `valid` flag at the end. Reach it through `borrow` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `borrow` twice with `amount` varied, and assert that the value `price-multi-resolve` returns is identical in both runs; a divergence confirms the finding.

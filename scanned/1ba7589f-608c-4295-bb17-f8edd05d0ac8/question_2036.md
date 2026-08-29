# Q2036: is-healthy-with-mask via collateral-remove: reprice every other holder's collateral in the same transa

## Question
Does `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107) let an unprivileged attacker who controls whether the position has any enabled debt row (the has-debt branch) reach `is-healthy-with-mask` (mainnet/contracts/market/v0-4-market.clar:663) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it resolves an egroup for a caller-influenced mask and applies its LTV-BORROW, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:663` -> `is-healthy-with-mask`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: whether the position has any enabled debt row (the has-debt branch)
- Exploit idea: `is-healthy-with-mask` resolves an egroup for a caller-influenced mask and applies its LTV-BORROW. Reach it through `collateral-remove` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `collateral-remove` twice with whether the position has any enabled debt row (the has-debt branch) varied, and assert that the value `is-healthy-with-mask` returns is identical in both runs; a divergence confirms the finding.

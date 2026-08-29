# Q4184: convert-to-scaled-debt via supply-collateral-add: reprice every other holder's collateral in the same transa

## Question
Does `supply-collateral-add` (mainnet/contracts/market/v0-4-market.clar:1175) let an unprivileged attacker who controls the `ft` trait principal deciding which vault is routed to reach `convert-to-scaled-debt` (mainnet/contracts/market/v0-4-market.clar:648) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it scales a token amount by the cached borrow index, rounding up on the borrow path, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:648` -> `convert-to-scaled-debt`
- Entrypoint: `supply-collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1175`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal deciding which vault is routed to
- Exploit idea: `convert-to-scaled-debt` scales a token amount by the cached borrow index, rounding up on the borrow path. Reach it through `supply-collateral-add` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `supply-collateral-add` twice with the `ft` trait principal deciding which vault is routed to varied, and assert that the value `convert-to-scaled-debt` returns is identical in both runs; a divergence confirms the finding.

# Q2912: calc-liq-factor-exp via liquidate: make a victim's position resolve to a worse efficiency gro

## Question
Does `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) let an unprivileged attacker who controls `collateral-receiver` reach `calc-liq-factor-exp` (mainnet/contracts/market/v0-4-market.clar:708) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it uses `(/ exp BPS)` as an integer exponent for `pow` and falls back to `sqrti` below BPS, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:708` -> `calc-liq-factor-exp`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `collateral-receiver`
- Exploit idea: `calc-liq-factor-exp` uses `(/ exp BPS)` as an integer exponent for `pow` and falls back to `sqrti` below BPS. Reach it through `liquidate` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `liquidate` twice with `collateral-receiver` varied, and assert that the value `calc-liq-factor-exp` returns is identical in both runs; a divergence confirms the finding.

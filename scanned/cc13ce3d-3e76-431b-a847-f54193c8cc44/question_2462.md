# Q2462: calc-liq-factor-exp via liquidate-multi: push a third party's position past a fold bound so every e

## Question
Entering through `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593) while controlling the trait principals supplied per entry, can an unprivileged attacker make `calc-liq-factor-exp` (mainnet/contracts/market/v0-4-market.clar:708) push a third party's position past a fold bound so every evaluation of it aborts? `calc-liq-factor-exp` uses `(/ exp BPS)` as an integer exponent for `pow` and falls back to `sqrti` below BPS, so the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends would fail, yielding protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:708` -> `calc-liq-factor-exp`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the trait principals supplied per entry
- Exploit idea: `calc-liq-factor-exp` uses `(/ exp BPS)` as an integer exponent for `pow` and falls back to `sqrti` below BPS. Reach it through `liquidate-multi` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `liquidate-multi` twice with the trait principals supplied per entry varied, and assert that the value `calc-liq-factor-exp` returns is identical in both runs; a divergence confirms the finding.

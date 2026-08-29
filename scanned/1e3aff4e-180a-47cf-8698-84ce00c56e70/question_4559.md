# Q4559: calc-liq-factor-exp via liquidate-redeem: route a victim's mandatory payout through a principal that

## Question
`calc-liq-factor-exp` (mainnet/contracts/market/v0-4-market.clar:708) uses `(/ exp BPS)` as an integer exponent for `pow` and falls back to `sqrti` below BPS. Can an unprivileged caller of `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604), by choosing the vault whose share price the redemption moves, use that to route a victim's mandatory payout through a principal that always rejects delivery, violating the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created and producing protocol insolvency through uncollateralised debt?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:708` -> `calc-liq-factor-exp`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the vault whose share price the redemption moves
- Exploit idea: `calc-liq-factor-exp` uses `(/ exp BPS)` as an integer exponent for `pow` and falls back to `sqrti` below BPS. Reach it through `liquidate-redeem` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Run the baseline `liquidate-redeem` call, then the attacker-shaped one with the vault whose share price the redemption moves, and assert the attacker's net token balance change is zero or negative.

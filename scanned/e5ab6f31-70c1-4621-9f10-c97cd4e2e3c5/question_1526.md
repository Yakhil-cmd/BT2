# Q1526: socialize-debt-asset via liquidate-redeem: route a victim's mandatory payout through a principal that

## Question
Entering through `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604) while controlling the vault whose share price the redemption moves, can an unprivileged attacker make `socialize-debt-asset` (mainnet/contracts/market/v0-4-market.clar:879) route a victim's mandatory payout through a principal that always rejects delivery? `socialize-debt-asset` calls the vault write-down, then overwrites `index-cache` for the current timestamp mid-fold, and carries a `success` flag that short-circuits, so the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created would fail, yielding protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:879` -> `socialize-debt-asset`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the vault whose share price the redemption moves
- Exploit idea: `socialize-debt-asset` calls the vault write-down, then overwrites `index-cache` for the current timestamp mid-fold, and carries a `success` flag that short-circuits. Reach it through `liquidate-redeem` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `liquidate-redeem` twice with the vault whose share price the redemption moves varied, and assert that the value `socialize-debt-asset` returns is identical in both runs; a divergence confirms the finding.

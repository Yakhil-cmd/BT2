# Q4538: resolve-interpolation-points via collateral-add: route a victim's mandatory payout through a principal that

## Question
Entering through `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020) while controlling call ordering within the block, can an unprivileged attacker make `resolve-interpolation-points` (mainnet/contracts/vault/v0-vault-stx.clar:205) route a victim's mandatory payout through a principal that always rejects delivery? `resolve-interpolation-points` selects the bracketing curve points for a utilization, so the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment would fail, yielding protocol insolvency.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:205` -> `resolve-interpolation-points`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: call ordering within the block
- Exploit idea: `resolve-interpolation-points` selects the bracketing curve points for a utilization. Reach it through `collateral-add` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `collateral-add` twice with call ordering within the block varied, and assert that the value `resolve-interpolation-points` returns is identical in both runs; a divergence confirms the finding.

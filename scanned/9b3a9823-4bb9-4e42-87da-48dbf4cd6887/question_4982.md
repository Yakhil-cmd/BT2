# Q4982: get-account-scaled-debt via repay: route a victim's mandatory payout through a principal that

## Question
Entering through `repay` (mainnet/contracts/market/v0-4-market.clar:1316) while controlling the `ft` trait principal, can an unprivileged attacker make `get-account-scaled-debt` (mainnet/contracts/market/v0-market-vault.clar:307) route a victim's mandatory payout through a principal that always rejects delivery? `get-account-scaled-debt` reads one scaled debt row, so the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more would fail, yielding protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:307` -> `get-account-scaled-debt`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `get-account-scaled-debt` reads one scaled debt row. Reach it through `repay` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `repay` twice with the `ft` trait principal varied, and assert that the value `get-account-scaled-debt` returns is identical in both runs; a divergence confirms the finding.

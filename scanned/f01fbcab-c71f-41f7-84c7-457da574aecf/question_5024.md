# Q5024: get-asset-value via borrow: route a victim's mandatory payout through a principal that

## Question
Does `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) let an unprivileged attacker who controls `amount` reach `get-asset-value` (mainnet/contracts/market/v0-4-market.clar:679) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it resolves a fresh price for a single asset and normalizes with a caller-supplied rounding direction, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:679` -> `get-asset-value`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `get-asset-value` resolves a fresh price for a single asset and normalizes with a caller-supplied rounding direction. Reach it through `borrow` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `borrow` twice with `amount` varied, and assert that the value `get-asset-value` returns is identical in both runs; a divergence confirms the finding.

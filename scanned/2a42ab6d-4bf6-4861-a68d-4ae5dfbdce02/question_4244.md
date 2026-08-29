# Q4244: total-assets-preview via transfer: route a victim's mandatory payout through a principal that

## Question
Does `transfer` (mainnet/contracts/vault/v0-vault-stx.clar:752) let an unprivileged attacker who controls the timing relative to a pledge or a liquidation reach `total-assets-preview` (mainnet/contracts/vault/v0-vault-stx.clar:341) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it re-derives a FORWARD index inside calls that have already accrued, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:341` -> `total-assets-preview`
- Entrypoint: `transfer` (`mainnet/contracts/vault/v0-vault-stx.clar:752`), unprivileged and publicly callable
- Attacker controls: the timing relative to a pledge or a liquidation
- Exploit idea: `total-assets-preview` re-derives a FORWARD index inside calls that have already accrued. Reach it through `transfer` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `transfer` twice with the timing relative to a pledge or a liquidation varied, and assert that the value `total-assets-preview` returns is identical in both runs; a divergence confirms the finding.

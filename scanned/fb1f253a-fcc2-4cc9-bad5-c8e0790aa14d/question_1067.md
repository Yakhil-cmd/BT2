# Q1067: receive-tokens via transfer: reprice every other holder's collateral in the same transa

## Question
`receive-tokens` (mainnet/contracts/market/v0-market-vault.clar:256) pulls an asset from a named account. Can an unprivileged caller of `transfer` (mainnet/contracts/vault/v0-vault-stx.clar:752), by choosing the timing relative to a pledge or a liquidation, use that to reprice every other holder's collateral in the same transaction that profits from it, violating the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment and producing protocol insolvency through uncollateralised debt?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:256` -> `receive-tokens`
- Entrypoint: `transfer` (`mainnet/contracts/vault/v0-vault-stx.clar:752`), unprivileged and publicly callable
- Attacker controls: the timing relative to a pledge or a liquidation
- Exploit idea: `receive-tokens` pulls an asset from a named account. Reach it through `transfer` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Run the baseline `transfer` call, then the attacker-shaped one with the timing relative to a pledge or a liquidation, and assert the attacker's net token balance change is zero or negative.

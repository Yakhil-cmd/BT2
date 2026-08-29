# Q4439: add-user-collateral via liquidate-redeem: write a stranger's ledger through an unsolicited on-behalf

## Question
`add-user-collateral` (mainnet/contracts/market/v0-market-vault.clar:198) adds to the collateral row with a graceful u0 default. Can an unprivileged caller of `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604), by choosing the vault whose share price the redemption moves, use that to write a stranger's ledger through an unsolicited on-behalf-of call, violating the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created and producing protocol insolvency?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:198` -> `add-user-collateral`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the vault whose share price the redemption moves
- Exploit idea: `add-user-collateral` adds to the collateral row with a graceful u0 default. Reach it through `liquidate-redeem` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Run the baseline `liquidate-redeem` call, then the attacker-shaped one with the vault whose share price the redemption moves, and assert the attacker's net token balance change is zero or negative.

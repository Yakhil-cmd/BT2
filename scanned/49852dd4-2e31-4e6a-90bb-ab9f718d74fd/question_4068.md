# Q4068: iter-lookup-collateral via liquidate: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) let an unprivileged attacker who controls `collateral-receiver` reach `iter-lookup-collateral` (mainnet/contracts/market/v0-market-vault.clar:180) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it skips rows failing `relevant`, so a disabled asset's collateral vanishes from the returned position, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:180` -> `iter-lookup-collateral`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `collateral-receiver`
- Exploit idea: `iter-lookup-collateral` skips rows failing `relevant`, so a disabled asset's collateral vanishes from the returned position. Reach it through `liquidate` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz `collateral-receiver` across its boundary values through `liquidate` in simnet and assert `iter-lookup-collateral` never returns a value that breaks the invariant.

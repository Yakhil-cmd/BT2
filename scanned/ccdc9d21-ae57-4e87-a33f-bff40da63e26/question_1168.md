# Q1168: get-egroup via collateral-remove-redeem: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211) let an unprivileged attacker who controls the zToken/underlying id mapping reached (the u100 sentinel branch) reach `get-egroup` (mainnet/contracts/market/v0-4-market.clar:460) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it resolves the efficiency group for a mask and is unwrapped with `try!` on every health path, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is theft of unclaimed yield.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:460` -> `get-egroup`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: the zToken/underlying id mapping reached (the u100 sentinel branch)
- Exploit idea: `get-egroup` resolves the efficiency group for a mask and is unwrapped with `try!` on every health path. Reach it through `collateral-remove-redeem` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: Set up the position in simnet, call `collateral-remove-redeem` with the zToken/underlying id mapping reached (the u100 sentinel branch), and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.

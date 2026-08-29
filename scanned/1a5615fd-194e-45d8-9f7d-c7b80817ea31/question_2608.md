# Q2608: send-tokens via collateral-remove-redeem: prime shared state so the next caller in the block is eval

## Question
Does `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211) let an unprivileged attacker who controls remaining zToken collateral whose price moves with the redeem reach `send-tokens` (mainnet/contracts/market/v0-market-vault.clar:259) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it pushes an asset to a caller-chosen recipient principal, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is theft of unclaimed yield.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:259` -> `send-tokens`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: remaining zToken collateral whose price moves with the redeem
- Exploit idea: `send-tokens` pushes an asset to a caller-chosen recipient principal. Reach it through `collateral-remove-redeem` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: Set up the position in simnet, call `collateral-remove-redeem` with remaining zToken collateral whose price moves with the redeem, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.

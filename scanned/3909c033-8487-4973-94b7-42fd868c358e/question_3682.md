# Q3682: send-tokens via repay: prime shared state so the next caller in the block is eval

## Question
Entering through `repay` (mainnet/contracts/market/v0-4-market.clar:1316) while controlling `amount`, including far above the real debt (the capping path), can an unprivileged attacker make `send-tokens` (mainnet/contracts/market/v0-market-vault.clar:259) prime shared state so the next caller in the block is evaluated against it? `send-tokens` pushes an asset to a caller-chosen recipient principal, so the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements would fail, yielding direct theft of user funds at rest or in motion.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:259` -> `send-tokens`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: `amount`, including far above the real debt (the capping path)
- Exploit idea: `send-tokens` pushes an asset to a caller-chosen recipient principal. Reach it through `repay` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: Set up the position in simnet, call `repay` with `amount`, including far above the real debt (the capping path), and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.

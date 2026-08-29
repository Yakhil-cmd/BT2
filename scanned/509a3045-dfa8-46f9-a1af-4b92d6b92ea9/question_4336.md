# Q4336: uint-to-list-u64 via collateral-add: prime shared state so the next caller in the block is eval

## Question
Does `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020) let an unprivileged attacker who controls `amount` reach `uint-to-list-u64` (mainnet/contracts/registry/v0-assets.clar:80) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it expands a bitmap into a 64-element list, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is direct theft of another user's collateral.

## Target
- File/function: `mainnet/contracts/registry/v0-assets.clar:80` -> `uint-to-list-u64`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `uint-to-list-u64` expands a bitmap into a 64-element list. Reach it through `collateral-add` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: Set up the position in simnet, call `collateral-add` with `amount`, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.

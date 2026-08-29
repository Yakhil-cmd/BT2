# Q2182: remove-user-collateral via repay: push a third party's position past a fold bound so every e

## Question
Entering through `repay` (mainnet/contracts/market/v0-4-market.clar:1316) while controlling whether the repaid asset is in the accrued debt list, can an unprivileged attacker make `remove-user-collateral` (mainnet/contracts/market/v0-market-vault.clar:205) push a third party's position past a fold bound so every evaluation of it aborts? `remove-user-collateral` asserts sufficiency then `map-delete`s only on an exact zero, so the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends would fail, yielding direct theft of another user's collateral.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:205` -> `remove-user-collateral`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: whether the repaid asset is in the accrued debt list
- Exploit idea: `remove-user-collateral` asserts sufficiency then `map-delete`s only on an exact zero. Reach it through `repay` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: Set up the position in simnet, call `repay` with whether the repaid asset is in the accrued debt list, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.

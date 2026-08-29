# Q1722: accrue-user-debts via borrow: route a victim's mandatory payout through a principal that

## Question
Entering through `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) while controlling `amount`, can an unprivileged attacker make `accrue-user-debts` (mainnet/contracts/market/v0-4-market.clar:259) route a victim's mandatory payout through a principal that always rejects delivery? `accrue-user-debts` folds accrual over the position's debt list only, so the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created would fail, yielding permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:259` -> `accrue-user-debts`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `accrue-user-debts` folds accrual over the position's debt list only. Reach it through `borrow` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `amount` across its boundary values through `borrow` in simnet and assert `accrue-user-debts` never returns a value that breaks the invariant.

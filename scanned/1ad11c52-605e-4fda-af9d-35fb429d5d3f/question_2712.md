# Q2712: mask-to-list-collateral via borrow: route a victim's mandatory payout through a principal that

## Question
Does `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) let an unprivileged attacker who controls `receiver`, including a contract principal reach `mask-to-list-collateral` (mainnet/contracts/market/v0-4-market.clar:449) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it expands a mask to a list of ids over ITER-UINT-64, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:449` -> `mask-to-list-collateral`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: `receiver`, including a contract principal
- Exploit idea: `mask-to-list-collateral` expands a mask to a list of ids over ITER-UINT-64. Reach it through `borrow` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `receiver`, including a contract principal across its boundary values through `borrow` in simnet and assert `mask-to-list-collateral` never returns a value that breaks the invariant.

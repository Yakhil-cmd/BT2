# Q4608: resolve-pyth via collateral-remove: route a victim's mandatory payout through a principal that

## Question
Does `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107) let an unprivileged attacker who controls whether the position has any enabled debt row (the has-debt branch) reach `resolve-pyth` (mainnet/contracts/market/v0-4-market.clar:312) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it reads the Pyth storage record for a 32-byte ident, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:312` -> `resolve-pyth`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: whether the position has any enabled debt row (the has-debt branch)
- Exploit idea: `resolve-pyth` reads the Pyth storage record for a 32-byte ident. Reach it through `collateral-remove` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz whether the position has any enabled debt row (the has-debt branch) across its boundary values through `collateral-remove` in simnet and assert `resolve-pyth` never returns a value that breaks the invariant.

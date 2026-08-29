# Q2112: mask-to-list-internal via collateral-remove-redeem: push a third party's position past a fold bound so every e

## Question
Does `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211) let an unprivileged attacker who controls the zToken/underlying id mapping reached (the u100 sentinel branch) reach `mask-to-list-internal` (mainnet/contracts/market/v0-4-market.clar:435) in a state where it push a third party's position past a fold bound so every evaluation of it aborts? Given that it expands mask bits into a list bounded at 64 entries, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is permanent freezing of a position that can never be closed.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:435` -> `mask-to-list-internal`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: the zToken/underlying id mapping reached (the u100 sentinel branch)
- Exploit idea: `mask-to-list-internal` expands mask bits into a list bounded at 64 entries. Reach it through `collateral-remove-redeem` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Fuzz the zToken/underlying id mapping reached (the u100 sentinel branch) across its boundary values through `collateral-remove-redeem` in simnet and assert `mask-to-list-internal` never returns a value that breaks the invariant.

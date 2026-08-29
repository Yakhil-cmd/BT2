# Q1345: convert-to-scaled-debt via liquidate: prime shared state so the next caller in the block is eval

## Question
Can an unprivileged attacker entering through `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382), controlling `debt-amount`, drive `convert-to-scaled-debt` (mainnet/contracts/market/v0-4-market.clar:648) — which scales a token amount by the cached borrow index, rounding up on the borrow path — to prime shared state so the next caller in the block is evaluated against it, breaking the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment, and cause direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:648` -> `convert-to-scaled-debt`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `debt-amount`
- Exploit idea: `convert-to-scaled-debt` scales a token amount by the cached borrow index, rounding up on the borrow path. Reach it through `liquidate` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `liquidate` with `debt-amount`, then read `convert-to-scaled-debt` state before and after in the same block and assert the two sides of the invariant are equal.

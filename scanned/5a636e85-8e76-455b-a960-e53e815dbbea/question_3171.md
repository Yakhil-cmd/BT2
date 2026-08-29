# Q3171: calc-liq-collateral-repay via liquidate-redeem: prime shared state so the next caller in the block is eval

## Question
`calc-liq-collateral-repay` (mainnet/contracts/market/v0-4-market.clar:728) scales the repaid debt by `(+ BPS liq-penalty)`. Can an unprivileged caller of `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604), by choosing the redemption receiver, use that to prime shared state so the next caller in the block is evaluated against it, violating the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block and producing permanent freezing of funds?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:728` -> `calc-liq-collateral-repay`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the redemption receiver
- Exploit idea: `calc-liq-collateral-repay` scales the repaid debt by `(+ BPS liq-penalty)`. Reach it through `liquidate-redeem` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Snapshot every state variable `calc-liq-collateral-repay` touches, run `liquidate-redeem` with the redemption receiver, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.

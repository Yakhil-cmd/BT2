# Q2115: calc-liquidation-params via liquidate-multi: seize from a position that is solvent under the mask its o

## Question
`calc-liquidation-params` (mainnet/contracts/market/v0-4-market.clar:739) chains the factor, the exponent curve, the penalty bound and the max repayable amount in one helper. Can an unprivileged caller of `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593), by choosing the full batch list and its ordering, use that to seize from a position that is solvent under the mask its own operations were validated against, violating the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more and producing permanent freezing of funds?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:739` -> `calc-liquidation-params`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the full batch list and its ordering
- Exploit idea: `calc-liquidation-params` chains the factor, the exponent curve, the penalty bound and the max repayable amount in one helper. Reach it through `liquidate-multi` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Snapshot every state variable `calc-liquidation-params` touches, run `liquidate-multi` with the full batch list and its ordering, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.

# Q2661: accrue-collateral-asset via redeem: seize from a position that is solvent under the mask its o

## Question
Can an unprivileged attacker entering through `redeem` (mainnet/contracts/vault/v0-vault-stx.clar:797), controlling `recipient`, drive `accrue-collateral-asset` (mainnet/contracts/market/v0-4-market.clar:273) — which maps a ztoken id to a vault id through a chain of `is-eq` tests that falls through to the u100 sentinel — to seize from a position that is solvent under the mask its own operations were validated against, breaking the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more, and cause permanent freezing of a position that can never be closed?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:273` -> `accrue-collateral-asset`
- Entrypoint: `redeem` (`mainnet/contracts/vault/v0-vault-stx.clar:797`), unprivileged and publicly callable
- Attacker controls: `recipient`
- Exploit idea: `accrue-collateral-asset` maps a ztoken id to a vault id through a chain of `is-eq` tests that falls through to the u100 sentinel. Reach it through `redeem` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Snapshot every state variable `accrue-collateral-asset` touches, run `redeem` with `recipient`, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.

# Q4641: interpolate-rate via liquidate-redeem: seize from a position that is solvent under the mask its o

## Question
Can an unprivileged attacker entering through `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604), controlling the seized zToken amount that is immediately redeemed, drive `interpolate-rate` (mainnet/contracts/vault/v0-vault-stx.clar:196) — which interpolates between packed u16 curve points — to seize from a position that is solvent under the mask its own operations were validated against, breaking the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created, and cause permanent freezing of a position that can never be closed?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:196` -> `interpolate-rate`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the seized zToken amount that is immediately redeemed
- Exploit idea: `interpolate-rate` interpolates between packed u16 curve points. Reach it through `liquidate-redeem` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Snapshot every state variable `interpolate-rate` touches, run `liquidate-redeem` with the seized zToken amount that is immediately redeemed, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.

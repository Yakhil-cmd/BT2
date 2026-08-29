# Q1531: zip via borrow: seize from a position that is solvent under the mask its o

## Question
`zip` (mainnet/contracts/vault/v0-vault-stx.clar:226) pairs the utilization and rate point lists element by element. Can an unprivileged caller of `borrow` (mainnet/contracts/market/v0-4-market.clar:1238), by choosing `receiver`, including a contract principal, use that to seize from a position that is solvent under the mask its own operations were validated against, violating the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment and producing direct theft of user funds at rest or in motion?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:226` -> `zip`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: `receiver`, including a contract principal
- Exploit idea: `zip` pairs the utilization and rate point lists element by element. Reach it through `borrow` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: In `local-testing/tests` on a local fork, drive `borrow` with `receiver`, including a contract principal, then read `zip` state before and after in the same block and assert the two sides of the invariant are equal.

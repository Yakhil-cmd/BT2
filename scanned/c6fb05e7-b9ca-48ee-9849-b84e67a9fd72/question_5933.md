# Q5933: iter-find-superset via borrow: reprice every other holder's collateral in the same transa

## Question
Can an unprivileged attacker entering through `borrow` (mainnet/contracts/market/v0-4-market.clar:1238), controlling the future mask produced by the new debt bit, drive `iter-find-superset` (mainnet/contracts/registry/v0-egroup.clar:267) — which short-circuits on the first superset match — to reprice every other holder's collateral in the same transaction that profits from it, breaking the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements, and cause protocol insolvency?

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:267` -> `iter-find-superset`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: the future mask produced by the new debt bit
- Exploit idea: `iter-find-superset` short-circuits on the first superset match. Reach it through `borrow` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Run the baseline `borrow` call, then the attacker-shaped one with the future mask produced by the new debt bit, and assert the attacker's net token balance change is zero or negative.

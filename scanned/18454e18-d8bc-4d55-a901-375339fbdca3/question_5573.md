# Q5573: resolve-callcode via collateral-remove: reprice every other holder's collateral in the same transa

## Question
Can an unprivileged attacker entering through `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107), controlling whether the position has any enabled debt row (the has-debt branch), drive `resolve-callcode` (mainnet/contracts/market/v0-4-market.clar:349) — which chains callcode transforms, with CALLCODE-ZSTSTX composing `resolve-ztoken` over `resolve-ststx` — to reprice every other holder's collateral in the same transaction that profits from it, breaking the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends, and cause protocol insolvency?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:349` -> `resolve-callcode`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: whether the position has any enabled debt row (the has-debt branch)
- Exploit idea: `resolve-callcode` chains callcode transforms, with CALLCODE-ZSTSTX composing `resolve-ztoken` over `resolve-ststx`. Reach it through `collateral-remove` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Run the baseline `collateral-remove` call, then the attacker-shaped one with whether the position has any enabled debt row (the has-debt branch), and assert the attacker's net token balance change is zero or negative.

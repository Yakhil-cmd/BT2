# Q3428: mask-to-list-internal via borrow: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) let an unprivileged attacker who controls the future mask produced by the new debt bit reach `mask-to-list-internal` (mainnet/contracts/market/v0-4-market.clar:435) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it expands mask bits into a list bounded at 64 entries, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is permanent freezing of unclaimed yield.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:435` -> `mask-to-list-internal`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: the future mask produced by the new debt bit
- Exploit idea: `mask-to-list-internal` expands mask bits into a list bounded at 64 entries. Reach it through `borrow` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: High - permanent freezing of unclaimed yield
- Fast validation: Write a Clarinet simnet test calling `borrow` twice with the future mask produced by the new debt bit varied, and assert that the value `mask-to-list-internal` returns is identical in both runs; a divergence confirms the finding.

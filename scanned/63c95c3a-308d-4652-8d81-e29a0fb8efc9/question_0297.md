# Q0297: active via collateral-add: write a stranger's ledger through an unsolicited on-behalf

## Question
Can an unprivileged attacker entering through `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020), controlling the three `price-feeds` buffers and their order, drive `active` (mainnet/contracts/registry/v0-egroup.clar:238) — which lists candidate bucket masks at or above a population — to write a stranger's ledger through an unsolicited on-behalf-of call, breaking the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements, and cause permanent freezing of funds?

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:238` -> `active`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: the three `price-feeds` buffers and their order
- Exploit idea: `active` lists candidate bucket masks at or above a population. Reach it through `collateral-add` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Snapshot every state variable `active` touches, run `collateral-add` with the three `price-feeds` buffers and their order, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.

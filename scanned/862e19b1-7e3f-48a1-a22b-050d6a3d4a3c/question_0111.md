# Q0111: uint-to-list-u64 via liquidate: push a third party's position past a fold bound so every e

## Question
`uint-to-list-u64` (mainnet/contracts/registry/v0-assets.clar:80) expands a bitmap into a 64-element list. Can an unprivileged caller of `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382), by choosing `min-collateral-expected`, use that to push a third party's position past a fold bound so every evaluation of it aborts, violating the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements and producing permanent freezing of funds?

## Target
- File/function: `mainnet/contracts/registry/v0-assets.clar:80` -> `uint-to-list-u64`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `min-collateral-expected`
- Exploit idea: `uint-to-list-u64` expands a bitmap into a 64-element list. Reach it through `liquidate` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Snapshot every state variable `uint-to-list-u64` touches, run `liquidate` with `min-collateral-expected`, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.

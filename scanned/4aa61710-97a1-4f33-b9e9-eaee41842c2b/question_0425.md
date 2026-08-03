# Q425: beneficiary resolution split via xcmpallet limited reserve transfer on Polkadot Relay XCM

## Question
Can an unprivileged attacker enter through `XcmPallet::limited_reserve_transfer_assets` on Polkadot Relay XCM and control nested `DescendOrigin`, `AliasOrigin`, `InitiateTransfer`, `DepositAsset`, or `Transact` instructions arranged to mutate local state mid-execution so that `XcmRouter` reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class, breaking the invariant that signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `relay/polkadot/src/xcm_config.rs` :: `XcmRouter`
- Entrypoint: `XcmPallet::limited_reserve_transfer_assets`
- Attacker controls: nested `DescendOrigin`, `AliasOrigin`, `InitiateTransfer`, `DepositAsset`, or `Transact` instructions arranged to mutate local state mid-execution
- Exploit idea: reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class
- Invariant to test: signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: stateful fuzz test over location, asset, and beneficiary permutations with assertions on issuance and backing

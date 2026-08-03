# Q2953: reserve-versus-teleport confusion via peoplekusama pallet xcm execute on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::execute` on People Kusama XCM and control nested `DescendOrigin`, `AliasOrigin`, `InitiateTransfer`, `DepositAsset`, or `Transact` instructions arranged to mutate local state mid-execution so that `XcmOriginToTransactDispatchOrigin` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `XcmOriginToTransactDispatchOrigin`
- Entrypoint: `PeopleKusama::pallet_xcm::execute`
- Attacker controls: nested `DescendOrigin`, `AliasOrigin`, `InitiateTransfer`, `DepositAsset`, or `Transact` instructions arranged to mutate local state mid-execution
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach

# Q1835: reserve-versus-teleport confusion via bridgehubpolkadot pallet xcm execute on Bridge Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `BridgeHubPolkadot::pallet_xcm::execute` on Bridge Hub Polkadot XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `MessageExporter` makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses, breaking the invariant that the same XCM message must never be treated as both paid and fee-waived for the same execution path, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs` :: `MessageExporter`
- Entrypoint: `BridgeHubPolkadot::pallet_xcm::execute`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses
- Invariant to test: the same XCM message must never be treated as both paid and fee-waived for the same execution path
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary

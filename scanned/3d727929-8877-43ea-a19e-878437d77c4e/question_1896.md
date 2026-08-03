# Q1896: message-export route confusion via assethubpolkadot signed user path on Bridge Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `AssetHubPolkadot signed user path that exports or routes XCM into BridgeHubPolkadot` on Bridge Hub Polkadot XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `FeeManager / WaivedLocations` causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume, breaking the invariant that the same XCM message must never be treated as both paid and fee-waived for the same execution path, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs` :: `FeeManager / WaivedLocations`
- Entrypoint: `AssetHubPolkadot signed user path that exports or routes XCM into BridgeHubPolkadot`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume
- Invariant to test: the same XCM message must never be treated as both paid and fee-waived for the same execution path
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary

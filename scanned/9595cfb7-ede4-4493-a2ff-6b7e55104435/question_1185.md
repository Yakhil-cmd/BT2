# Q1185: safe-call filter mismatch via polkadotxcm send on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::send` on Asset Hub Polkadot XCM and control a HOLLAR-like foreign asset whose reserve classification changes depending on origin and asset shape so that `HollarFromHydration` causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume, breaking the invariant that the same XCM message must never be treated as both paid and fee-waived for the same execution path, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `HollarFromHydration`
- Entrypoint: `PolkadotXcm::send`
- Attacker controls: a HOLLAR-like foreign asset whose reserve classification changes depending on origin and asset shape
- Exploit idea: causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume
- Invariant to test: the same XCM message must never be treated as both paid and fee-waived for the same execution path
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary

# Q1272: origin-conversion mismatch via polkadotxcm send on Asset Hub Kusama XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::send` on Asset Hub Kusama XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `PoolAssetsExchanger` causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume, breaking the invariant that asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations, and leading to high - stuck queue or persistent denial of service on a critical transfer path?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs` :: `PoolAssetsExchanger`
- Entrypoint: `PolkadotXcm::send`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume
- Invariant to test: asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations
- Expected Immunefi impact: High - stuck queue or persistent denial of service on a critical transfer path
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary

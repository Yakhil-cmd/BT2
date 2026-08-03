# Q1267: beneficiary resolution split via polkadotxcm send on Asset Hub Kusama XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::send` on Asset Hub Kusama XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `AssetTransactors` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that the same XCM message must never be treated as both paid and fee-waived for the same execution path, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs` :: `AssetTransactors`
- Entrypoint: `PolkadotXcm::send`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: the same XCM message must never be treated as both paid and fee-waived for the same execution path
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances

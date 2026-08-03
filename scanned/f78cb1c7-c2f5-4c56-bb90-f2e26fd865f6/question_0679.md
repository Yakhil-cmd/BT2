# Q679: beneficiary resolution split via xcmpallet limited reserve transfer on Kusama Relay XCM

## Question
Can an unprivileged attacker enter through `XcmPallet::limited_reserve_transfer_assets` on Kusama Relay XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `XcmRouter` makes pre-dispatch fee estimation and final withdrawal disagree on the effective asset, payer, or beneficiary, breaking the invariant that asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `relay/kusama/src/xcm_config.rs` :: `XcmRouter`
- Entrypoint: `XcmPallet::limited_reserve_transfer_assets`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: makes pre-dispatch fee estimation and final withdrawal disagree on the effective asset, payer, or beneficiary
- Invariant to test: asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach

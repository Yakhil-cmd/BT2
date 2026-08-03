# Q3736: beneficiary resolution split via encointer pallet xcm send on Encointer XCM

## Question
Can an unprivileged attacker enter through `Encointer::pallet_xcm::send` on Encointer XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `XcmOriginToTransactDispatchOrigin` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/encointer/src/xcm_config.rs` :: `XcmOriginToTransactDispatchOrigin`
- Entrypoint: `Encointer::pallet_xcm::send`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: asset backing must remain consistent across local balances, foreign assets, pool assets, reserve-backed assets, and bridged representations
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances

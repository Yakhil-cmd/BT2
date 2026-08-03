# Q696: message-export route confusion via xcmpallet send on Kusama Relay XCM

## Question
Can an unprivileged attacker enter through `XcmPallet::send` on Kusama Relay XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `LocalOriginConverter` causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume, breaking the invariant that delivery, execution, and refund accounting must not let a user extract more value than was actually debited, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `relay/kusama/src/xcm_config.rs` :: `LocalOriginConverter`
- Entrypoint: `XcmPallet::send`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume
- Invariant to test: delivery, execution, and refund accounting must not let a user extract more value than was actually debited
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: stateful fuzz test over location, asset, and beneficiary permutations with assertions on issuance and backing

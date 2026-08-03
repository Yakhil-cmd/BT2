# Q690: query or topic reuse via xcmpallet send on Kusama Relay XCM

## Question
Can an unprivileged attacker enter through `XcmPallet::send` on Kusama Relay XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `SovereignAccountOf` causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume, breaking the invariant that signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `relay/kusama/src/xcm_config.rs` :: `SovereignAccountOf`
- Entrypoint: `XcmPallet::send`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume
- Invariant to test: signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances

# Q524: fee-asset undercharge path via xcmpallet send on Polkadot Relay XCM

## Question
Can an unprivileged attacker enter through `XcmPallet::send` on Polkadot Relay XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `FeeManager / Aliasers` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that the same XCM message must never be treated as both paid and fee-waived for the same execution path, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `relay/polkadot/src/xcm_config.rs` :: `FeeManager / Aliasers`
- Entrypoint: `XcmPallet::send`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: the same XCM message must never be treated as both paid and fee-waived for the same execution path
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances

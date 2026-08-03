# Q402: waived-execution bypass via xcmpallet send on Polkadot Relay XCM

## Question
Can an unprivileged attacker enter through `XcmPallet::send` on Polkadot Relay XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `SovereignAccountOf` causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume, breaking the invariant that signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `relay/polkadot/src/xcm_config.rs` :: `SovereignAccountOf`
- Entrypoint: `XcmPallet::send`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume
- Invariant to test: signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances

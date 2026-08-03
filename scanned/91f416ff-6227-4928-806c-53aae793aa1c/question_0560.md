# Q560: origin-conversion mismatch via xcmpallet execute on Polkadot Relay XCM

## Question
Can an unprivileged attacker enter through `XcmPallet::execute` on Polkadot Relay XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `SovereignAccountOf` forces the runtime to treat the same asset as local in one step and foreign, reserve-backed, or bridged in another, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to high - stuck queue or persistent denial of service on a critical transfer path?

## Target
- File/function: `relay/polkadot/src/xcm_config.rs` :: `SovereignAccountOf`
- Entrypoint: `XcmPallet::execute`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: forces the runtime to treat the same asset as local in one step and foreign, reserve-backed, or bridged in another
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: High - stuck queue or persistent denial of service on a critical transfer path
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances

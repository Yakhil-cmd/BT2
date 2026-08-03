# Q566: message-export route confusion via xcmpallet send on Polkadot Relay XCM

## Question
Can an unprivileged attacker enter through `XcmPallet::send` on Polkadot Relay XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `LocalOriginConverter` reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class, breaking the invariant that signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `relay/polkadot/src/xcm_config.rs` :: `LocalOriginConverter`
- Entrypoint: `XcmPallet::send`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class
- Invariant to test: signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances

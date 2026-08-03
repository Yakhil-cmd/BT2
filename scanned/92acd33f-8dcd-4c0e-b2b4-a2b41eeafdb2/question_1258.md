# Q1258: message-export route confusion via polkadotxcm send on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::send` on Asset Hub Polkadot XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `XcmOriginToTransactDispatchOrigin` reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class, breaking the invariant that delivery, execution, and refund accounting must not let a user extract more value than was actually debited, and leading to critical - unauthorized local execution with direct loss of funds?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `XcmOriginToTransactDispatchOrigin`
- Entrypoint: `PolkadotXcm::send`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: reaches an exporter, alias, teleporter, or reserve path that should only be reachable from a tighter origin class
- Invariant to test: delivery, execution, and refund accounting must not let a user extract more value than was actually debited
- Expected Immunefi impact: Critical - unauthorized local execution with direct loss of funds
- Fast validation: stateful fuzz test over location, asset, and beneficiary permutations with assertions on issuance and backing

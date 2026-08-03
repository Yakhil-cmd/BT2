# Q1222: waived-execution bypass via polkadotxcm send on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::send` on Asset Hub Polkadot XCM and control a HOLLAR-like foreign asset whose reserve classification changes depending on origin and asset shape so that `TrustedAliasers` causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume, breaking the invariant that delivery, execution, and refund accounting must not let a user extract more value than was actually debited, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `TrustedAliasers`
- Entrypoint: `PolkadotXcm::send`
- Attacker controls: a HOLLAR-like foreign asset whose reserve classification changes depending on origin and asset shape
- Exploit idea: causes origin conversion to resolve a more privileged or different effective local origin than the barrier and fee path assume
- Invariant to test: delivery, execution, and refund accounting must not let a user extract more value than was actually debited
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: stateful fuzz test over location, asset, and beneficiary permutations with assertions on issuance and backing

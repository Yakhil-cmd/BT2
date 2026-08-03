# Q1099: beneficiary resolution split via polkadotxcm transfer assets on Asset Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `PolkadotXcm::transfer_assets` on Asset Hub Polkadot XCM and control an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls so that `AssetTransactors` makes pre-dispatch fee estimation and final withdrawal disagree on the effective asset, payer, or beneficiary, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs` :: `AssetTransactors`
- Entrypoint: `PolkadotXcm::transfer_assets`
- Attacker controls: an XCM payload with attacker-chosen origin-shaping instructions, fee asset, beneficiary, and nested `Transact` calls
- Exploit idea: makes pre-dispatch fee estimation and final withdrawal disagree on the effective asset, payer, or beneficiary
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: stateful fuzz test over location, asset, and beneficiary permutations with assertions on issuance and backing

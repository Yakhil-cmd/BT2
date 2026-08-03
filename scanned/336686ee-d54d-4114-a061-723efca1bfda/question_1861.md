# Q1861: beneficiary resolution split via signed user flow whose on Bridge Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `signed user flow whose message enters BridgeHubPolkadot through a valid upstream XCM route` on Bridge Hub Polkadot XCM and control an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message so that `TrustedAliasers` makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses, breaking the invariant that signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs` :: `TrustedAliasers`
- Entrypoint: `signed user flow whose message enters BridgeHubPolkadot through a valid upstream XCM route`
- Attacker controls: an asset set that mixes native, foreign, pooled, reserve-backed, or bridged representations in one message
- Exploit idea: makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses
- Invariant to test: signed users and user-controlled remote messages must never obtain Root, system-parachain, relay, or privileged plurality execution
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary

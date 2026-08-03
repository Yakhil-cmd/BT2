# Q1948: Snowbridge export bypass via signed user flow whose on Bridge Hub Polkadot XCM

## Question
Can an unprivileged attacker enter through `signed user flow whose message enters BridgeHubPolkadot through a valid upstream XCM route` on Bridge Hub Polkadot XCM and control a location that can be interpreted differently across aliasing, account conversion, and asset transacting code so that `MessageExporter` makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses, breaking the invariant that delivery, execution, and refund accounting must not let a user extract more value than was actually debited, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs` :: `MessageExporter`
- Entrypoint: `signed user flow whose message enters BridgeHubPolkadot through a valid upstream XCM route`
- Attacker controls: a location that can be interpreted differently across aliasing, account conversion, and asset transacting code
- Exploit idea: makes `DenyExportMessageFrom`, `MessageExporter` ordering, or `LocationAsSuperuser` disagree with the origin and destination the runtime actually uses
- Invariant to test: delivery, execution, and refund accounting must not let a user extract more value than was actually debited
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary

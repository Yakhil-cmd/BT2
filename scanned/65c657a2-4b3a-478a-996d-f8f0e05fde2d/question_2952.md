# Q2952: fee-asset undercharge path via peoplekusama pallet xcm send on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::send` on People Kusama XCM and control nested `DescendOrigin`, `AliasOrigin`, `InitiateTransfer`, `DepositAsset`, or `Transact` instructions arranged to mutate local state mid-execution so that `LocationToAccountId` induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations, breaking the invariant that reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `LocationToAccountId`
- Entrypoint: `PeopleKusama::pallet_xcm::send`
- Attacker controls: nested `DescendOrigin`, `AliasOrigin`, `InitiateTransfer`, `DepositAsset`, or `Transact` instructions arranged to mutate local state mid-execution
- Exploit idea: induces a state where execution succeeds but assets are trapped, miscredited, replayed, or double-accounted across local and remote representations
- Invariant to test: reserve-transfer, teleport, and exporter filters must not be bypassable with attacker-shaped message structure
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances

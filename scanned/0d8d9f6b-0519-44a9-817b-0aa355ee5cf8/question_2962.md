# Q2962: fee-asset undercharge path via peoplekusama pallet xcm execute on People Kusama XCM

## Question
Can an unprivileged attacker enter through `PeopleKusama::pallet_xcm::execute` on People Kusama XCM and control nested `DescendOrigin`, `AliasOrigin`, `InitiateTransfer`, `DepositAsset`, or `Transact` instructions arranged to mutate local state mid-execution so that `XcmOriginToTransactDispatchOrigin` makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does, breaking the invariant that location-to-account conversion must stay injective enough for all accepted user and XCM flows, and leading to high - stuck queue or persistent denial of service on a critical transfer path?

## Target
- File/function: `system-parachains/people/people-kusama/src/xcm_config.rs` :: `XcmOriginToTransactDispatchOrigin`
- Entrypoint: `PeopleKusama::pallet_xcm::execute`
- Attacker controls: nested `DescendOrigin`, `AliasOrigin`, `InitiateTransfer`, `DepositAsset`, or `Transact` instructions arranged to mutate local state mid-execution
- Exploit idea: makes the barrier admit execution while the fee or asset path evaluates a different context than dispatch does
- Invariant to test: location-to-account conversion must stay injective enough for all accepted user and XCM flows
- Expected Immunefi impact: High - stuck queue or persistent denial of service on a critical transfer path
- Fast validation: differential test comparing origin/barrier resolution with the final dispatch origin and beneficiary

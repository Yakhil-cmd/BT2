# Q384: reserve-release ordering via utility batch all around on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `Utility::batch_all` around multiple `AhOps` calls on Asset Hub operations pallet and control withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot so that `Pallet::withdraw_crowdloan_contribution` creates a partial-success path where the caller receives value but the backing reserve or contribution accounting is still considered live elsewhere, breaking the invariant that a crowdloan or lease-backed balance must only become withdrawable once and only by the rightful beneficiary, and leading to critical - permanent freeze or misdelivery of migrated user funds?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `Pallet::withdraw_crowdloan_contribution`
- Entrypoint: `Utility::batch_all` around multiple `AhOps` calls
- Attacker controls: withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot
- Exploit idea: creates a partial-success path where the caller receives value but the backing reserve or contribution accounting is still considered live elsewhere
- Invariant to test: a crowdloan or lease-backed balance must only become withdrawable once and only by the rightful beneficiary
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of migrated user funds
- Fast validation: runtime integration test over repeated withdraw/unreserve ordering with reserve and balance assertions

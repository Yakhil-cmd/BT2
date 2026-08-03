# Q400: sovereign-translation mismatch via ahops transfer to post on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `AhOps::transfer_to_post_migration_treasury` on Asset Hub operations pallet and control withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot so that `Pallet::unreserve_lease_deposit` creates a partial-success path where the caller receives value but the backing reserve or contribution accounting is still considered live elsewhere, breaking the invariant that a crowdloan or lease-backed balance must only become withdrawable once and only by the rightful beneficiary, and leading to high - critical accounting corruption across migration and contribution cleanup flows?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `Pallet::unreserve_lease_deposit`
- Entrypoint: `AhOps::transfer_to_post_migration_treasury`
- Attacker controls: withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot
- Exploit idea: creates a partial-success path where the caller receives value but the backing reserve or contribution accounting is still considered live elsewhere
- Invariant to test: a crowdloan or lease-backed balance must only become withdrawable once and only by the rightful beneficiary
- Expected Immunefi impact: High - critical accounting corruption across migration and contribution cleanup flows
- Fast validation: stateful fuzz test over block, depositor, and para_id combinations with one-shot-withdraw invariants

# Q312: reserve-release ordering via ahops unreserve lease deposit on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `AhOps::unreserve_lease_deposit` on Asset Hub operations pallet and control withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot so that `Pallet::transfer_to_post_migration_treasury` lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance, breaking the invariant that reserve release, contribution withdrawal, and treasury transfer must reconcile exactly with the remaining backing state, and leading to high - critical accounting corruption across migration and contribution cleanup flows?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `Pallet::transfer_to_post_migration_treasury`
- Entrypoint: `AhOps::unreserve_lease_deposit`
- Attacker controls: withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot
- Exploit idea: lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance
- Invariant to test: reserve release, contribution withdrawal, and treasury transfer must reconcile exactly with the remaining backing state
- Expected Immunefi impact: High - critical accounting corruption across migration and contribution cleanup flows
- Fast validation: test that drives treasury transfer across migration-complete boundaries and verifies exact source/destination balances

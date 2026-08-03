# Q261: crowdloan-withdraw replay via ahops unreserve crowdloan reserve on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `AhOps::unreserve_crowdloan_reserve` on Asset Hub operations pallet and control withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot so that `Pallet::unreserve_crowdloan_reserve` lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance, breaking the invariant that a crowdloan or lease-backed balance must only become withdrawable once and only by the rightful beneficiary, and leading to critical - direct loss of funds from crowdloan, lease, or treasury accounting?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `Pallet::unreserve_crowdloan_reserve`
- Entrypoint: `AhOps::unreserve_crowdloan_reserve`
- Attacker controls: withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot
- Exploit idea: lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance
- Invariant to test: a crowdloan or lease-backed balance must only become withdrawable once and only by the rightful beneficiary
- Expected Immunefi impact: Critical - direct loss of funds from crowdloan, lease, or treasury accounting
- Fast validation: test that drives treasury transfer across migration-complete boundaries and verifies exact source/destination balances

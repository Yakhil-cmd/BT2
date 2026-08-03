# Q331: crowdloan-withdraw replay via utility batch all around on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `Utility::batch_all` around multiple `AhOps` calls on Asset Hub operations pallet and control withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot so that `do_unreserve_lease_deposit / do_withdraw_crowdloan_contribution / do_unreserve_crowdloan_reserve` lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance, breaking the invariant that partial failures must not leave the user paid while the reserve, hold, or pot accounting still claims the value exists, and leading to critical - permanent freeze or misdelivery of migrated user funds?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `do_unreserve_lease_deposit / do_withdraw_crowdloan_contribution / do_unreserve_crowdloan_reserve`
- Entrypoint: `Utility::batch_all` around multiple `AhOps` calls
- Attacker controls: withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot
- Exploit idea: lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance
- Invariant to test: partial failures must not leave the user paid while the reserve, hold, or pot accounting still claims the value exists
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of migrated user funds
- Fast validation: test that drives treasury transfer across migration-complete boundaries and verifies exact source/destination balances

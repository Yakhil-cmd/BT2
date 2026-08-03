# Q361: crowdloan-withdraw replay via ahops unreserve crowdloan reserve on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `AhOps::unreserve_crowdloan_reserve` on Asset Hub operations pallet and control withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot so that `Pallet::unreserve_crowdloan_reserve` lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance, breaking the invariant that migration-related account translation helpers must not enable value movement to the wrong sovereign account, and leading to critical - permanent freeze or misdelivery of migrated user funds?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `Pallet::unreserve_crowdloan_reserve`
- Entrypoint: `AhOps::unreserve_crowdloan_reserve`
- Attacker controls: withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot
- Exploit idea: lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance
- Invariant to test: migration-related account translation helpers must not enable value movement to the wrong sovereign account
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of migrated user funds
- Fast validation: test that drives treasury transfer across migration-complete boundaries and verifies exact source/destination balances

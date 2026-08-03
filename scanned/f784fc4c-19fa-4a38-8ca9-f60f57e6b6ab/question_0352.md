# Q352: reserve-release ordering via utility batch all around on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `Utility::batch_all` around multiple `AhOps` calls on Asset Hub operations pallet and control withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot so that `Pallet::withdraw_crowdloan_contribution` lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance, breaking the invariant that migration-related account translation helpers must not enable value movement to the wrong sovereign account, and leading to critical - direct loss of funds from crowdloan, lease, or treasury accounting?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `Pallet::withdraw_crowdloan_contribution`
- Entrypoint: `Utility::batch_all` around multiple `AhOps` calls
- Attacker controls: withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot
- Exploit idea: lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance
- Invariant to test: migration-related account translation helpers must not enable value movement to the wrong sovereign account
- Expected Immunefi impact: Critical - direct loss of funds from crowdloan, lease, or treasury accounting
- Fast validation: test that drives treasury transfer across migration-complete boundaries and verifies exact source/destination balances

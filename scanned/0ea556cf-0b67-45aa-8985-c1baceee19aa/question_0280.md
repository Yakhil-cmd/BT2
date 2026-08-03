# Q280: sovereign-translation mismatch via ahops withdraw crowdloan contribution on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `AhOps::withdraw_crowdloan_contribution` on Asset Hub operations pallet and control withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot so that `do_unreserve_lease_deposit / do_withdraw_crowdloan_contribution / do_unreserve_crowdloan_reserve` lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance, breaking the invariant that a crowdloan or lease-backed balance must only become withdrawable once and only by the rightful beneficiary, and leading to high - critical accounting corruption across migration and contribution cleanup flows?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `do_unreserve_lease_deposit / do_withdraw_crowdloan_contribution / do_unreserve_crowdloan_reserve`
- Entrypoint: `AhOps::withdraw_crowdloan_contribution`
- Attacker controls: withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot
- Exploit idea: lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance
- Invariant to test: a crowdloan or lease-backed balance must only become withdrawable once and only by the rightful beneficiary
- Expected Immunefi impact: High - critical accounting corruption across migration and contribution cleanup flows
- Fast validation: stateful fuzz test over block, depositor, and para_id combinations with one-shot-withdraw invariants

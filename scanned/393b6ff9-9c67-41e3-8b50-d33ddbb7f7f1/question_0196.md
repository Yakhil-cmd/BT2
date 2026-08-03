# Q196: sovereign-translation mismatch via ahops withdraw crowdloan contribution on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `AhOps::withdraw_crowdloan_contribution` on Asset Hub operations pallet and control the target block, `depositor` override, `para_id`, and whether the same storage slot is reachable through another user-visible flow so that `do_unreserve_lease_deposit / do_withdraw_crowdloan_contribution / do_unreserve_crowdloan_reserve` makes sovereign-account translation helpers disagree with later value-moving logic about the rightful account mapping, breaking the invariant that partial failures must not leave the user paid while the reserve, hold, or pot accounting still claims the value exists, and leading to critical - direct loss of funds from crowdloan, lease, or treasury accounting?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `do_unreserve_lease_deposit / do_withdraw_crowdloan_contribution / do_unreserve_crowdloan_reserve`
- Entrypoint: `AhOps::withdraw_crowdloan_contribution`
- Attacker controls: the target block, `depositor` override, `para_id`, and whether the same storage slot is reachable through another user-visible flow
- Exploit idea: makes sovereign-account translation helpers disagree with later value-moving logic about the rightful account mapping
- Invariant to test: partial failures must not leave the user paid while the reserve, hold, or pot accounting still claims the value exists
- Expected Immunefi impact: Critical - direct loss of funds from crowdloan, lease, or treasury accounting
- Fast validation: runtime integration test over repeated withdraw/unreserve ordering with reserve and balance assertions

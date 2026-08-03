# Q290: sovereign-translation mismatch via ahops unreserve crowdloan reserve on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `AhOps::unreserve_crowdloan_reserve` on Asset Hub operations pallet and control withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot so that `try_translate_rc_sovereign_to_ah / try_rc_sovereign_derived_to_ah` lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance, breaking the invariant that reserve release, contribution withdrawal, and treasury transfer must reconcile exactly with the remaining backing state, and leading to critical - direct loss of funds from crowdloan, lease, or treasury accounting?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `try_translate_rc_sovereign_to_ah / try_rc_sovereign_derived_to_ah`
- Entrypoint: `AhOps::unreserve_crowdloan_reserve`
- Attacker controls: withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot
- Exploit idea: lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance
- Invariant to test: reserve release, contribution withdrawal, and treasury transfer must reconcile exactly with the remaining backing state
- Expected Immunefi impact: Critical - direct loss of funds from crowdloan, lease, or treasury accounting
- Fast validation: stateful fuzz test over block, depositor, and para_id combinations with one-shot-withdraw invariants

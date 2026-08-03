# Q359: treasury-transfer boundary via ahops withdraw crowdloan contribution on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `AhOps::withdraw_crowdloan_contribution` on Asset Hub operations pallet and control withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot so that `Pallet::withdraw_crowdloan_contribution` lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance, breaking the invariant that migration-related account translation helpers must not enable value movement to the wrong sovereign account, and leading to critical - permanent freeze or misdelivery of migrated user funds?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `Pallet::withdraw_crowdloan_contribution`
- Entrypoint: `AhOps::withdraw_crowdloan_contribution`
- Attacker controls: withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot
- Exploit idea: lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance
- Invariant to test: migration-related account translation helpers must not enable value movement to the wrong sovereign account
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of migrated user funds
- Fast validation: stateful fuzz test over block, depositor, and para_id combinations with one-shot-withdraw invariants

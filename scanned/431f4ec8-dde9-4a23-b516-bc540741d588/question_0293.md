# Q293: crowdloan-withdraw replay via ahops unreserve crowdloan reserve on Asset Hub operations pallet

## Question
Can an unprivileged attacker enter through `AhOps::unreserve_crowdloan_reserve` on Asset Hub operations pallet and control withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot so that `Pallet::unreserve_crowdloan_reserve` lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance, breaking the invariant that reserve release, contribution withdrawal, and treasury transfer must reconcile exactly with the remaining backing state, and leading to critical - permanent freeze or misdelivery of migrated user funds?

## Target
- File/function: `pallets/ah-ops/src/lib.rs` :: `Pallet::unreserve_crowdloan_reserve`
- Entrypoint: `AhOps::unreserve_crowdloan_reserve`
- Attacker controls: withdraw timing around lease expiry, prior auto-unreserve, and a partially updated crowdloan pot
- Exploit idea: lets the caller withdraw or unreserve value that should still be backing a crowdloan, lease deposit, or treasury balance
- Invariant to test: reserve release, contribution withdrawal, and treasury transfer must reconcile exactly with the remaining backing state
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of migrated user funds
- Fast validation: runtime integration test over repeated withdraw/unreserve ordering with reserve and balance assertions

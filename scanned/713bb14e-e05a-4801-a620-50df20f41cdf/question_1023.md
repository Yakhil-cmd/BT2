# Q1023: cross-pallet hold mismatch via proxy proxy multisig as on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Kusama Relay runtime and control repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries so that `impl pallet_nomination_pools::Config` forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules, breaking the invariant that unlocking state, holds, and reserves must stay consistent across all touched pallets, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries
- Exploit idea: forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules
- Invariant to test: unlocking state, holds, and reserves must stay consistent across all touched pallets
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

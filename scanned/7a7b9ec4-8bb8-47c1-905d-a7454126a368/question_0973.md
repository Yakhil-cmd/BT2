# Q973: reward-accounting drift via proxy proxy multisig as on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Kusama Relay runtime and control repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries so that `impl pallet_rc_migrator::Config` forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules, breaking the invariant that XCM-triggered and local transitions must preserve the same accounting rules, and leading to high - unintended runtime behaviour with concrete user loss?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries
- Exploit idea: forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules
- Invariant to test: XCM-triggered and local transitions must preserve the same accounting rules
- Expected Immunefi impact: High - unintended runtime behaviour with concrete user loss
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

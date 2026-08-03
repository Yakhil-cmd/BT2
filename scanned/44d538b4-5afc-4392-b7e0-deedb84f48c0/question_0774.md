# Q774: pool-versus-staking split via nominationpools join bond extra on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Polkadot Relay runtime and control repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries so that `impl pallet_rc_migrator::Config` makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries
- Exploit idea: makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

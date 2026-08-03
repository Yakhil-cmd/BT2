# Q824: double-withdraw edge via nominationpools join bond extra on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Polkadot Relay runtime and control nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions so that `impl pallet_rc_migrator::Config` forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to high - network-wide halt or stuck critical queue?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions
- Exploit idea: forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: High - network-wide halt or stuck critical queue
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

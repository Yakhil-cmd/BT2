# Q890: unlock-ordering mismatch via nominationpools join bond extra on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Polkadot Relay runtime and control nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions so that `impl pallet_rc_migrator::Config` makes issuance, rewards, or held and reserved balances drift from what users can actually withdraw, breaking the invariant that one pool share, claim, contribution, or unlock chunk may only be exited or consumed once, and leading to high - unintended runtime behaviour with concrete user loss?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions
- Exploit idea: makes issuance, rewards, or held and reserved balances drift from what users can actually withdraw
- Invariant to test: one pool share, claim, contribution, or unlock chunk may only be exited or consumed once
- Expected Immunefi impact: High - unintended runtime behaviour with concrete user loss
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary

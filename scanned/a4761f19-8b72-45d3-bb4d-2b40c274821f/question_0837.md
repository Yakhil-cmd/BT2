# Q837: reward-accounting drift via claims claim claim attest on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Claims::{claim, claim_attest, move_claim}` on Polkadot Relay runtime and control nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions so that `impl pallet_nomination_pools::Config` makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `Claims::{claim, claim_attest, move_claim}`
- Attacker controls: nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions
- Exploit idea: makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

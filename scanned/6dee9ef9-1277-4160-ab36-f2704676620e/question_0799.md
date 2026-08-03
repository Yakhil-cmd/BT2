# Q799: proxy-batch privilege widening via nominationpools join bond extra on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Polkadot Relay runtime and control attacker-chosen claim parameters, destination accounts, or attestation ordering so that `impl pallet_staking::Config` obtains a second payout, claim, or withdrawal after a first transition partially succeeded, breaking the invariant that unlocking state, holds, and reserves must stay consistent across all touched pallets, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_staking::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: attacker-chosen claim parameters, destination accounts, or attestation ordering
- Exploit idea: obtains a second payout, claim, or withdrawal after a first transition partially succeeded
- Invariant to test: unlocking state, holds, and reserves must stay consistent across all touched pallets
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

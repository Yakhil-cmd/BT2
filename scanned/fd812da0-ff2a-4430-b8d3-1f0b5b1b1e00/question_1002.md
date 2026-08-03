# Q1002: double-withdraw edge via nominationpools join bond extra on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Kusama Relay runtime and control attacker-chosen claim parameters, destination accounts, or attestation ordering so that `impl pallet_nomination_pools::Config` obtains a second payout, claim, or withdrawal after a first transition partially succeeded, breaking the invariant that XCM-triggered and local transitions must preserve the same accounting rules, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: attacker-chosen claim parameters, destination accounts, or attestation ordering
- Exploit idea: obtains a second payout, claim, or withdrawal after a first transition partially succeeded
- Invariant to test: XCM-triggered and local transitions must preserve the same accounting rules
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

# Q761: crowdloan exit inconsistency via staking bond unbond rebond on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Staking::{bond, unbond, rebond, nominate, payout_stakers}` on Polkadot Relay runtime and control repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `Staking::{bond, unbond, rebond, nominate, payout_stakers}`
- Attacker controls: repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries
- Exploit idea: forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

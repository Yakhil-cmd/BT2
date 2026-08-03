# Q795: cross-pallet hold mismatch via nominationpools join bond extra on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Polkadot Relay runtime and control crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` converts a user-controlled call into a more privileged or differently metered runtime path, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries
- Exploit idea: converts a user-controlled call into a more privileged or differently metered runtime path
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary

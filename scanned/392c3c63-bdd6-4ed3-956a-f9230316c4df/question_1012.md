# Q1012: pool-versus-staking split via claims claim claim attest on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `Claims::{claim, claim_attest, move_claim}` on Kusama Relay runtime and control crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` converts a user-controlled call into a more privileged or differently metered runtime path, breaking the invariant that no signed user can turn a normal call into a privileged or underpriced state change, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `Claims::{claim, claim_attest, move_claim}`
- Attacker controls: crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries
- Exploit idea: converts a user-controlled call into a more privileged or differently metered runtime path
- Invariant to test: no signed user can turn a normal call into a privileged or underpriced state change
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary

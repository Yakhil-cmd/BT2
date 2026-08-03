# Q976: unlock-ordering mismatch via crowdloan contribute withdraw on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `Crowdloan::{contribute, withdraw}` on Kusama Relay runtime and control repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` converts a user-controlled call into a more privileged or differently metered runtime path, breaking the invariant that user-controlled batching must not bypass staking, pool, claim, or proxy restrictions, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `Crowdloan::{contribute, withdraw}`
- Attacker controls: repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries
- Exploit idea: converts a user-controlled call into a more privileged or differently metered runtime path
- Invariant to test: user-controlled batching must not bypass staking, pool, claim, or proxy restrictions
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

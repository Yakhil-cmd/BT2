# Q3650: cross-ceremony state bleed via runtimecall encointercommunities signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerCommunities` signed user path on Encointer runtime and control XCM or proxy execution layered around community payout or reputation-consuming flows so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` causes a payout, faucet action, or bazaar settlement to finalize locally without the matching burn, hold, or reputation consumption, breaking the invariant that XCM-assisted flows must not mint, unlock, or strand more value than they debit locally, and leading to critical - unbacked or duplicated community balances?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `RuntimeCall::EncointerCommunities` signed user path
- Attacker controls: XCM or proxy execution layered around community payout or reputation-consuming flows
- Exploit idea: causes a payout, faucet action, or bazaar settlement to finalize locally without the matching burn, hold, or reputation consumption
- Invariant to test: XCM-assisted flows must not mint, unlock, or strand more value than they debit locally
- Expected Immunefi impact: Critical - unbacked or duplicated community balances
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions

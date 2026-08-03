# Q3648: offline-payment double-spend via polkadotxcm execute send on Encointer runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on Encointer runtime and control batched calls spanning balances, ceremonies, treasuries, bazaar, and democracy modules so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` makes community balances, treasuries, and reputation state disagree about which value was already spent or earned, breaking the invariant that XCM-assisted flows must not mint, unlock, or strand more value than they debit locally, and leading to critical - unbacked or duplicated community balances?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: batched calls spanning balances, ceremonies, treasuries, bazaar, and democracy modules
- Exploit idea: makes community balances, treasuries, and reputation state disagree about which value was already spent or earned
- Invariant to test: XCM-assisted flows must not mint, unlock, or strand more value than they debit locally
- Expected Immunefi impact: Critical - unbacked or duplicated community balances
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions

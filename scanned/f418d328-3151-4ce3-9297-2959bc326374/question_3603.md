# Q3603: reputation-consumption replay via proxy proxy utility batch on Encointer runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around Encointer calls on Encointer runtime and control batched calls spanning balances, ceremonies, treasuries, bazaar, and democracy modules so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` makes community balances, treasuries, and reputation state disagree about which value was already spent or earned, breaking the invariant that each reputation, meetup result, offline payment, or treasury claim must be consumable exactly once and only in its own context, and leading to critical - unbacked or duplicated community balances?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around Encointer calls
- Attacker controls: batched calls spanning balances, ceremonies, treasuries, bazaar, and democracy modules
- Exploit idea: makes community balances, treasuries, and reputation state disagree about which value was already spent or earned
- Invariant to test: each reputation, meetup result, offline payment, or treasury claim must be consumable exactly once and only in its own context
- Expected Immunefi impact: Critical - unbacked or duplicated community balances
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries

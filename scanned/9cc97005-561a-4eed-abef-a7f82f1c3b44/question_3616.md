# Q3616: offline-payment double-spend via proxy proxy utility batch on Encointer runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around Encointer calls on Encointer runtime and control batched calls spanning balances, ceremonies, treasuries, bazaar, and democracy modules so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` makes community balances, treasuries, and reputation state disagree about which value was already spent or earned, breaking the invariant that batched or proxied execution must not let a user bypass ceremony or community isolation rules, and leading to critical - permanent freeze of community funds?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around Encointer calls
- Attacker controls: batched calls spanning balances, ceremonies, treasuries, bazaar, and democracy modules
- Exploit idea: makes community balances, treasuries, and reputation state disagree about which value was already spent or earned
- Invariant to test: batched or proxied execution must not let a user bypass ceremony or community isolation rules
- Expected Immunefi impact: Critical - permanent freeze of community funds
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries

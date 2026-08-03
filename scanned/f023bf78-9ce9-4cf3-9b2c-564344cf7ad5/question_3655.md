# Q3655: reputation-consumption replay via proxy proxy utility batch on Encointer runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around Encointer calls on Encointer runtime and control batched calls spanning balances, ceremonies, treasuries, bazaar, and democracy modules so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated, breaking the invariant that community treasury and issued balances must always reconcile after user-triggered flows, and leading to critical - unbacked or duplicated community balances?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around Encointer calls
- Attacker controls: batched calls spanning balances, ceremonies, treasuries, bazaar, and democracy modules
- Exploit idea: lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated
- Invariant to test: community treasury and issued balances must always reconcile after user-triggered flows
- Expected Immunefi impact: Critical - unbacked or duplicated community balances
- Fast validation: xcm or proxy integration test if the path depends on aliased or remote execution

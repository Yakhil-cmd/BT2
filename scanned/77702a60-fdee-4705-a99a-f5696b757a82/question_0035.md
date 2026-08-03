# Q35: account-mapping collision via multisig as multi remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof on Asset-Hub remote proxy flow and control a `real` account whose local-to-remote mapping may collide or downgrade unexpectedly so that `Pallet::remote_proxy` lets a previously valid authorization be replayed across a changed remote or local security context, breaking the invariant that registered proofs must not be reusable, swappable, or consumable out of order across nested calls, and leading to critical - unauthorized dispatch as another account with direct loss of funds?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::remote_proxy`
- Entrypoint: `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof
- Attacker controls: a `real` account whose local-to-remote mapping may collide or downgrade unexpectedly
- Exploit idea: lets a previously valid authorization be replayed across a changed remote or local security context
- Invariant to test: registered proofs must not be reusable, swappable, or consumable out of order across nested calls
- Expected Immunefi impact: Critical - unauthorized dispatch as another account with direct loss of funds
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

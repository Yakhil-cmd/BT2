# Q13: proof-stack confusion via pallet remote proxy remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `pallet_remote_proxy::remote_proxy` on Asset-Hub remote proxy flow and control multiple registered proofs whose LIFO consumption order can be attacker-shaped through nested dispatch so that `Pallet::do_remote_proxy` lets a previously valid authorization be replayed across a changed remote or local security context, breaking the invariant that registered proofs must not be reusable, swappable, or consumable out of order across nested calls, and leading to critical - unauthorized dispatch as another account with direct loss of funds?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::do_remote_proxy`
- Entrypoint: `pallet_remote_proxy::remote_proxy`
- Attacker controls: multiple registered proofs whose LIFO consumption order can be attacker-shaped through nested dispatch
- Exploit idea: lets a previously valid authorization be replayed across a changed remote or local security context
- Invariant to test: registered proofs must not be reusable, swappable, or consumable out of order across nested calls
- Expected Immunefi impact: Critical - unauthorized dispatch as another account with direct loss of funds
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

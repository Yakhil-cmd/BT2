# Q97: proof-stack confusion via register remote proxy proof on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `register_remote_proxy_proof + remote_proxy_with_registered_proof` in one transaction on Asset-Hub remote proxy flow and control a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination so that `Pallet::remote_proxy` causes the wrong registered proof to be popped and consumed by a different wrapped call than the user intended, breaking the invariant that local-to-remote account conversion and remote-to-local proxy mapping must not widen authority or collide between users, and leading to critical - unauthorized privileged state transition through a replayed remote proof?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::remote_proxy`
- Entrypoint: `register_remote_proxy_proof + remote_proxy_with_registered_proof` in one transaction
- Attacker controls: a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination
- Exploit idea: causes the wrong registered proof to be popped and consumed by a different wrapped call than the user intended
- Invariant to test: local-to-remote account conversion and remote-to-local proxy mapping must not widen authority or collide between users
- Expected Immunefi impact: Critical - unauthorized privileged state transition through a replayed remote proof
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

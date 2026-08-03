# Q2: proxy-type widening via register remote proxy proof on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `register_remote_proxy_proof + remote_proxy_with_registered_proof` in one transaction on Asset-Hub remote proxy flow and control a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination so that `Pallet::register_remote_proxy_proof` admits a stale or mismatched proof after the remote authorization should no longer be usable, breaking the invariant that local-to-remote account conversion and remote-to-local proxy mapping must not widen authority or collide between users, and leading to critical - unauthorized dispatch as another account with direct loss of funds?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::register_remote_proxy_proof`
- Entrypoint: `register_remote_proxy_proof + remote_proxy_with_registered_proof` in one transaction
- Attacker controls: a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination
- Exploit idea: admits a stale or mismatched proof after the remote authorization should no longer be usable
- Invariant to test: local-to-remote account conversion and remote-to-local proxy mapping must not widen authority or collide between users
- Expected Immunefi impact: Critical - unauthorized dispatch as another account with direct loss of funds
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

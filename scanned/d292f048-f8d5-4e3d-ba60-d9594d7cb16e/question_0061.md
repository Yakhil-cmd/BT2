# Q61: proof-stack confusion via register remote proxy proof on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `register_remote_proxy_proof + remote_proxy_with_registered_proof` in one transaction on Asset-Hub remote proxy flow and control a `RelayChain` proof anchored near the storage-root retention boundary so that `Pallet::do_remote_proxy` resolves the proof, real account, or proxy definition against different identities across validation and dispatch, breaking the invariant that revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close, and leading to critical - unauthorized privileged state transition through a replayed remote proof?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::do_remote_proxy`
- Entrypoint: `register_remote_proxy_proof + remote_proxy_with_registered_proof` in one transaction
- Attacker controls: a `RelayChain` proof anchored near the storage-root retention boundary
- Exploit idea: resolves the proof, real account, or proxy definition against different identities across validation and dispatch
- Invariant to test: revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close
- Expected Immunefi impact: Critical - unauthorized privileged state transition through a replayed remote proof
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

# Q121: proof-stack confusion via utility batch all register on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Utility::batch_all([register_remote_proxy_proof, remote_proxy_with_registered_proof])` on Asset-Hub remote proxy flow and control a `RelayChain` proof anchored near the storage-root retention boundary so that `Pallet::remote_proxy` admits a stale or mismatched proof after the remote authorization should no longer be usable, breaking the invariant that a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants, and leading to critical - unauthorized dispatch as another account with direct loss of funds?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::remote_proxy`
- Entrypoint: `Utility::batch_all([register_remote_proxy_proof, remote_proxy_with_registered_proof])`
- Attacker controls: a `RelayChain` proof anchored near the storage-root retention boundary
- Exploit idea: admits a stale or mismatched proof after the remote authorization should no longer be usable
- Invariant to test: a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants
- Expected Immunefi impact: Critical - unauthorized dispatch as another account with direct loss of funds
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

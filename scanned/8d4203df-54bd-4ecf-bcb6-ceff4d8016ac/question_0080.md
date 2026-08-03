# Q80: stale proof replay via pallet remote proxy remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `pallet_remote_proxy::remote_proxy` on Asset-Hub remote proxy flow and control a `RelayChain` proof anchored near the storage-root retention boundary so that `Pallet::do_remote_proxy` resolves the proof, real account, or proxy definition against different identities across validation and dispatch, breaking the invariant that local-to-remote account conversion and remote-to-local proxy mapping must not widen authority or collide between users, and leading to critical - unauthorized privileged state transition through a replayed remote proof?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::do_remote_proxy`
- Entrypoint: `pallet_remote_proxy::remote_proxy`
- Attacker controls: a `RelayChain` proof anchored near the storage-root retention boundary
- Exploit idea: resolves the proof, real account, or proxy definition against different identities across validation and dispatch
- Invariant to test: local-to-remote account conversion and remote-to-local proxy mapping must not widen authority or collide between users
- Expected Immunefi impact: Critical - unauthorized privileged state transition through a replayed remote proof
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

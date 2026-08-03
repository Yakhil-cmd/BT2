# Q58: proxy-type widening via utility batch all register on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Utility::batch_all([register_remote_proxy_proof, remote_proxy_with_registered_proof])` on Asset-Hub remote proxy flow and control a `real` account whose local-to-remote mapping may collide or downgrade unexpectedly so that `BlockToRoot / RemoteProxyContext` resolves the proof, real account, or proxy definition against different identities across validation and dispatch, breaking the invariant that local-to-remote account conversion and remote-to-local proxy mapping must not widen authority or collide between users, and leading to critical - unauthorized privileged state transition through a replayed remote proof?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `BlockToRoot / RemoteProxyContext`
- Entrypoint: `Utility::batch_all([register_remote_proxy_proof, remote_proxy_with_registered_proof])`
- Attacker controls: a `real` account whose local-to-remote mapping may collide or downgrade unexpectedly
- Exploit idea: resolves the proof, real account, or proxy definition against different identities across validation and dispatch
- Invariant to test: local-to-remote account conversion and remote-to-local proxy mapping must not widen authority or collide between users
- Expected Immunefi impact: Critical - unauthorized privileged state transition through a replayed remote proof
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

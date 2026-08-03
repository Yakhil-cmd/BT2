# Q130: proxy-type widening via multisig as multi remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof on Asset-Hub remote proxy flow and control a `real` account whose local-to-remote mapping may collide or downgrade unexpectedly so that `BlockToRoot / RemoteProxyContext` resolves the proof, real account, or proxy definition against different identities across validation and dispatch, breaking the invariant that registered proofs must not be reusable, swappable, or consumable out of order across nested calls, and leading to critical - unauthorized privileged state transition through a replayed remote proof?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `BlockToRoot / RemoteProxyContext`
- Entrypoint: `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof
- Attacker controls: a `real` account whose local-to-remote mapping may collide or downgrade unexpectedly
- Exploit idea: resolves the proof, real account, or proxy definition against different identities across validation and dispatch
- Invariant to test: registered proofs must not be reusable, swappable, or consumable out of order across nested calls
- Expected Immunefi impact: Critical - unauthorized privileged state transition through a replayed remote proof
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

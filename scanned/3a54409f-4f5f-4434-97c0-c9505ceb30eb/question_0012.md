# Q12: stale proof replay via proxy proxy remote proxy on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path on Asset-Hub remote proxy flow and control a `real` account whose local-to-remote mapping may collide or downgrade unexpectedly so that `Pallet::register_remote_proxy_proof` causes the wrong registered proof to be popped and consumed by a different wrapped call than the user intended, breaking the invariant that revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close, and leading to high - critical call-path denial of service through proof-context corruption?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::register_remote_proxy_proof`
- Entrypoint: `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path
- Attacker controls: a `real` account whose local-to-remote mapping may collide or downgrade unexpectedly
- Exploit idea: causes the wrong registered proof to be popped and consumed by a different wrapped call than the user intended
- Invariant to test: revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close
- Expected Immunefi impact: High - critical call-path denial of service through proof-context corruption
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

# Q99: account-mapping collision via proxy proxy remote proxy on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path on Asset-Hub remote proxy flow and control a `real` account whose local-to-remote mapping may collide or downgrade unexpectedly so that `Pallet::remote_proxy_with_registered_proof` admits a stale or mismatched proof after the remote authorization should no longer be usable, breaking the invariant that a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants, and leading to critical - unauthorized dispatch as another account with direct loss of funds?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::remote_proxy_with_registered_proof`
- Entrypoint: `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path
- Attacker controls: a `real` account whose local-to-remote mapping may collide or downgrade unexpectedly
- Exploit idea: admits a stale or mismatched proof after the remote authorization should no longer be usable
- Invariant to test: a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants
- Expected Immunefi impact: Critical - unauthorized dispatch as another account with direct loss of funds
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

# Q60: stale proof replay via proxy proxy remote proxy on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path on Asset-Hub remote proxy flow and control a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended so that `Pallet::register_remote_proxy_proof` lets a previously valid authorization be replayed across a changed remote or local security context, breaking the invariant that a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants, and leading to critical - unauthorized dispatch as another account with direct loss of funds?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::register_remote_proxy_proof`
- Entrypoint: `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path
- Attacker controls: a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended
- Exploit idea: lets a previously valid authorization be replayed across a changed remote or local security context
- Invariant to test: a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants
- Expected Immunefi impact: Critical - unauthorized dispatch as another account with direct loss of funds
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

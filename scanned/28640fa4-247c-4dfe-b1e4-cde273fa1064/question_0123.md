# Q123: account-mapping collision via proxy proxy remote proxy on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path on Asset-Hub remote proxy flow and control multiple registered proofs whose LIFO consumption order can be attacker-shaped through nested dispatch so that `Pallet::remote_proxy_with_registered_proof` lets a previously valid authorization be replayed across a changed remote or local security context, breaking the invariant that a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants, and leading to high - critical call-path denial of service through proof-context corruption?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::remote_proxy_with_registered_proof`
- Entrypoint: `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path
- Attacker controls: multiple registered proofs whose LIFO consumption order can be attacker-shaped through nested dispatch
- Exploit idea: lets a previously valid authorization be replayed across a changed remote or local security context
- Invariant to test: a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants
- Expected Immunefi impact: High - critical call-path denial of service through proof-context corruption
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

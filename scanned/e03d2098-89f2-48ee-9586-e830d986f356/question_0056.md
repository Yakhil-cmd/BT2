# Q56: stale proof replay via proxy proxy remote proxy on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path on Asset-Hub remote proxy flow and control a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended so that `Pallet::remote_proxy_with_registered_proof` causes the wrong registered proof to be popped and consumed by a different wrapped call than the user intended, breaking the invariant that revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close, and leading to high - critical call-path denial of service through proof-context corruption?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::remote_proxy_with_registered_proof`
- Entrypoint: `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path
- Attacker controls: a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended
- Exploit idea: causes the wrong registered proof to be popped and consumed by a different wrapped call than the user intended
- Invariant to test: revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close
- Expected Immunefi impact: High - critical call-path denial of service through proof-context corruption
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

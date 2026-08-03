# Q44: stale proof replay via proxy proxy remote proxy on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path on Asset-Hub remote proxy flow and control a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination so that `BlockToRoot / RemoteProxyContext` makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call, breaking the invariant that revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close, and leading to critical - unauthorized privileged state transition through a replayed remote proof?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `BlockToRoot / RemoteProxyContext`
- Entrypoint: `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path
- Attacker controls: a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination
- Exploit idea: makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call
- Invariant to test: revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close
- Expected Immunefi impact: Critical - unauthorized privileged state transition through a replayed remote proof
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

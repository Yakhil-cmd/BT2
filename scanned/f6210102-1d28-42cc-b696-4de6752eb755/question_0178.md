# Q178: proxy-type widening via proxy proxy remote proxy on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path on Asset-Hub remote proxy flow and control a `RelayChain` proof anchored near the storage-root retention boundary so that `BlockToRoot / RemoteProxyContext` admits a stale or mismatched proof after the remote authorization should no longer be usable, breaking the invariant that revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close, and leading to high - critical call-path denial of service through proof-context corruption?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `BlockToRoot / RemoteProxyContext`
- Entrypoint: `Proxy::proxy(... -> remote_proxy ...)` nesting a local proxy around the remote-proxy path
- Attacker controls: a `RelayChain` proof anchored near the storage-root retention boundary
- Exploit idea: admits a stale or mismatched proof after the remote authorization should no longer be usable
- Invariant to test: revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close
- Expected Immunefi impact: High - critical call-path denial of service through proof-context corruption
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

# Q106: proxy-type widening via multisig as multi remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof on Asset-Hub remote proxy flow and control a `RelayChain` proof anchored near the storage-root retention boundary so that `BlockToRoot / RemoteProxyContext` causes the wrong registered proof to be popped and consumed by a different wrapped call than the user intended, breaking the invariant that a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants, and leading to high - critical call-path denial of service through proof-context corruption?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `BlockToRoot / RemoteProxyContext`
- Entrypoint: `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof
- Attacker controls: a `RelayChain` proof anchored near the storage-root retention boundary
- Exploit idea: causes the wrong registered proof to be popped and consumed by a different wrapped call than the user intended
- Invariant to test: a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants
- Expected Immunefi impact: High - critical call-path denial of service through proof-context corruption
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

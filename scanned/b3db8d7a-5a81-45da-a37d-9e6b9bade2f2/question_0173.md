# Q173: proof-stack confusion via utility batch all register on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Utility::batch_all([register_remote_proxy_proof, remote_proxy_with_registered_proof])` on Asset-Hub remote proxy flow and control a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination so that `BlockToRoot / RemoteProxyContext` makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call, breaking the invariant that revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close, and leading to high - critical call-path denial of service through proof-context corruption?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `BlockToRoot / RemoteProxyContext`
- Entrypoint: `Utility::batch_all([register_remote_proxy_proof, remote_proxy_with_registered_proof])`
- Attacker controls: a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination
- Exploit idea: makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call
- Invariant to test: revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close
- Expected Immunefi impact: High - critical call-path denial of service through proof-context corruption
- Fast validation: fuzz test over account mapping and proxy-definition conversion with privilege-equality assertions

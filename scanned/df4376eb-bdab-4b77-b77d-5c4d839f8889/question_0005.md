# Q5: proof-stack confusion via pallet remote proxy remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `pallet_remote_proxy::remote_proxy` on Asset-Hub remote proxy flow and control multiple registered proofs whose LIFO consumption order can be attacker-shaped through nested dispatch so that `BlockToRoot / RemoteProxyContext` admits a stale or mismatched proof after the remote authorization should no longer be usable, breaking the invariant that revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close, and leading to critical - unauthorized dispatch as another account with direct loss of funds?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `BlockToRoot / RemoteProxyContext`
- Entrypoint: `pallet_remote_proxy::remote_proxy`
- Attacker controls: multiple registered proofs whose LIFO consumption order can be attacker-shaped through nested dispatch
- Exploit idea: admits a stale or mismatched proof after the remote authorization should no longer be usable
- Invariant to test: revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close
- Expected Immunefi impact: Critical - unauthorized dispatch as another account with direct loss of funds
- Fast validation: fuzz test over account mapping and proxy-definition conversion with privilege-equality assertions

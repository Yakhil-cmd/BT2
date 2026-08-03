# Q110: proxy-type widening via multisig as multi remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof on Asset-Hub remote proxy flow and control a `RelayChain` proof anchored near the storage-root retention boundary so that `RemoteProxyInterface::local_to_remote_account_id / remote_to_local_proxy_defintion` makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call, breaking the invariant that revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close, and leading to critical - unauthorized dispatch as another account with direct loss of funds?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `RemoteProxyInterface::local_to_remote_account_id / remote_to_local_proxy_defintion`
- Entrypoint: `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof
- Attacker controls: a `RelayChain` proof anchored near the storage-root retention boundary
- Exploit idea: makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call
- Invariant to test: revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close
- Expected Immunefi impact: Critical - unauthorized dispatch as another account with direct loss of funds
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

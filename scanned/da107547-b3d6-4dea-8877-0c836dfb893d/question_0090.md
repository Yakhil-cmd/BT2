# Q90: proxy-type widening via utility batch all register on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Utility::batch_all([register_remote_proxy_proof, remote_proxy_with_registered_proof])` on Asset-Hub remote proxy flow and control a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended so that `Pallet::do_remote_proxy` admits a stale or mismatched proof after the remote authorization should no longer be usable, breaking the invariant that revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close, and leading to high - critical call-path denial of service through proof-context corruption?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::do_remote_proxy`
- Entrypoint: `Utility::batch_all([register_remote_proxy_proof, remote_proxy_with_registered_proof])`
- Attacker controls: a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended
- Exploit idea: admits a stale or mismatched proof after the remote authorization should no longer be usable
- Invariant to test: revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close
- Expected Immunefi impact: High - critical call-path denial of service through proof-context corruption
- Fast validation: fuzz test over account mapping and proxy-definition conversion with privilege-equality assertions

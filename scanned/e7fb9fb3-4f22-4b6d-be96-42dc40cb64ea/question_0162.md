# Q162: proxy-type widening via multisig as multi remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof on Asset-Hub remote proxy flow and control a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended so that `Pallet::do_remote_proxy` admits a stale or mismatched proof after the remote authorization should no longer be usable, breaking the invariant that a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants, and leading to high - critical call-path denial of service through proof-context corruption?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::do_remote_proxy`
- Entrypoint: `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof
- Attacker controls: a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended
- Exploit idea: admits a stale or mismatched proof after the remote authorization should no longer be usable
- Invariant to test: a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants
- Expected Immunefi impact: High - critical call-path denial of service through proof-context corruption
- Fast validation: fuzz test over account mapping and proxy-definition conversion with privilege-equality assertions

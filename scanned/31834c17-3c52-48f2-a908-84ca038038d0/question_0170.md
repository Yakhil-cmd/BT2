# Q170: proxy-type widening via multisig as multi remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof on Asset-Hub remote proxy flow and control a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended so that `Pallet::register_remote_proxy_proof` makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call, breaking the invariant that local-to-remote account conversion and remote-to-local proxy mapping must not widen authority or collide between users, and leading to high - critical call-path denial of service through proof-context corruption?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::register_remote_proxy_proof`
- Entrypoint: `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof
- Attacker controls: a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended
- Exploit idea: makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call
- Invariant to test: local-to-remote account conversion and remote-to-local proxy mapping must not widen authority or collide between users
- Expected Immunefi impact: High - critical call-path denial of service through proof-context corruption
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

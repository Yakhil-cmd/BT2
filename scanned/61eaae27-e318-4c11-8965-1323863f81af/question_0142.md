# Q142: proxy-type widening via multisig as multi remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof on Asset-Hub remote proxy flow and control multiple registered proofs whose LIFO consumption order can be attacker-shaped through nested dispatch so that `Pallet::remote_proxy_with_registered_proof` lets a previously valid authorization be replayed across a changed remote or local security context, breaking the invariant that registered proofs must not be reusable, swappable, or consumable out of order across nested calls, and leading to high - critical call-path denial of service through proof-context corruption?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::remote_proxy_with_registered_proof`
- Entrypoint: `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof
- Attacker controls: multiple registered proofs whose LIFO consumption order can be attacker-shaped through nested dispatch
- Exploit idea: lets a previously valid authorization be replayed across a changed remote or local security context
- Invariant to test: registered proofs must not be reusable, swappable, or consumable out of order across nested calls
- Expected Immunefi impact: High - critical call-path denial of service through proof-context corruption
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

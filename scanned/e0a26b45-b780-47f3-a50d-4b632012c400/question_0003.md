# Q3: account-mapping collision via utility batch all register on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Utility::batch_all([register_remote_proxy_proof, remote_proxy_with_registered_proof])` on Asset-Hub remote proxy flow and control a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended so that `Pallet::remote_proxy_with_registered_proof` makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call, breaking the invariant that registered proofs must not be reusable, swappable, or consumable out of order across nested calls, and leading to critical - unauthorized privileged state transition through a replayed remote proof?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::remote_proxy_with_registered_proof`
- Entrypoint: `Utility::batch_all([register_remote_proxy_proof, remote_proxy_with_registered_proof])`
- Attacker controls: a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended
- Exploit idea: makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call
- Invariant to test: registered proofs must not be reusable, swappable, or consumable out of order across nested calls
- Expected Immunefi impact: Critical - unauthorized privileged state transition through a replayed remote proof
- Fast validation: nested batch and multisig test asserting exactly which proof is popped and which call consumes it

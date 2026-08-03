# Q6: proxy-type widening via register remote proxy proof on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `register_remote_proxy_proof + remote_proxy_with_registered_proof` in one transaction on Asset-Hub remote proxy flow and control a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination so that `Pallet::remote_proxy` makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call, breaking the invariant that a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants, and leading to critical - unauthorized privileged state transition through a replayed remote proof?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::remote_proxy`
- Entrypoint: `register_remote_proxy_proof + remote_proxy_with_registered_proof` in one transaction
- Attacker controls: a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination
- Exploit idea: makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call
- Invariant to test: a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants
- Expected Immunefi impact: Critical - unauthorized privileged state transition through a replayed remote proof
- Fast validation: fuzz test over account mapping and proxy-definition conversion with privilege-equality assertions

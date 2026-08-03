# Q21: proof-stack confusion via pallet remote proxy remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `pallet_remote_proxy::remote_proxy` on Asset-Hub remote proxy flow and control a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination so that `Pallet::register_remote_proxy_proof` causes the wrong registered proof to be popped and consumed by a different wrapped call than the user intended, breaking the invariant that a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants, and leading to critical - unauthorized dispatch as another account with direct loss of funds?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::register_remote_proxy_proof`
- Entrypoint: `pallet_remote_proxy::remote_proxy`
- Attacker controls: a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination
- Exploit idea: causes the wrong registered proof to be popped and consumed by a different wrapped call than the user intended
- Invariant to test: a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants
- Expected Immunefi impact: Critical - unauthorized dispatch as another account with direct loss of funds
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

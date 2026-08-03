# Q116: stale proof replay via pallet remote proxy remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `pallet_remote_proxy::remote_proxy` on Asset-Hub remote proxy flow and control a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination so that `Pallet::remote_proxy` makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call, breaking the invariant that a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants, and leading to critical - unauthorized privileged state transition through a replayed remote proof?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::remote_proxy`
- Entrypoint: `pallet_remote_proxy::remote_proxy`
- Attacker controls: a wrapped call, proxy type, and proof bundle that are valid separately but dangerous in combination
- Exploit idea: makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call
- Invariant to test: a remote proxy authorization must only dispatch the exact local privilege that the current remote proof grants
- Expected Immunefi impact: Critical - unauthorized privileged state transition through a replayed remote proof
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

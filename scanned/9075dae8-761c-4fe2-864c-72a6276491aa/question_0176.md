# Q176: stale proof replay via register remote proxy proof on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `register_remote_proxy_proof + remote_proxy_with_registered_proof` in one transaction on Asset-Hub remote proxy flow and control multiple registered proofs whose LIFO consumption order can be attacker-shaped through nested dispatch so that `Pallet::do_remote_proxy` makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call, breaking the invariant that revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close, and leading to critical - unauthorized dispatch as another account with direct loss of funds?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::do_remote_proxy`
- Entrypoint: `register_remote_proxy_proof + remote_proxy_with_registered_proof` in one transaction
- Attacker controls: multiple registered proofs whose LIFO consumption order can be attacker-shaped through nested dispatch
- Exploit idea: makes local and remote proxy-type checks disagree on the effective privilege of the wrapped call
- Invariant to test: revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close
- Expected Immunefi impact: Critical - unauthorized dispatch as another account with direct loss of funds
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

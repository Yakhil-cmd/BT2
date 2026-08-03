# Q71: account-mapping collision via multisig as multi remote on Asset-Hub remote proxy flow

## Question
Can an unprivileged attacker enter through `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof on Asset-Hub remote proxy flow and control a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended so that `Pallet::do_remote_proxy` admits a stale or mismatched proof after the remote authorization should no longer be usable, breaking the invariant that revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close, and leading to critical - unauthorized dispatch as another account with direct loss of funds?

## Target
- File/function: `pallets/remote-proxy/src/lib.rs` :: `Pallet::do_remote_proxy`
- Entrypoint: `Multisig::as_multi(remote_proxy_with_registered_proof(...))` finalized with a fresh proof
- Attacker controls: a proof for a proxy definition that decodes but may map to a looser local `ProxyDefinition` than intended
- Exploit idea: admits a stale or mismatched proof after the remote authorization should no longer be usable
- Invariant to test: revocation or expiry on the remote side must become locally unexploitable once the retention window is supposed to close
- Expected Immunefi impact: Critical - unauthorized dispatch as another account with direct loss of funds
- Fast validation: unit test stale-proof reuse after remote revocation and root-window rollover

# Q839: proxy-batch privilege widening via proxy proxy multisig as on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Polkadot Relay runtime and control crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries so that `impl pallet_nomination_pools::Config` converts a user-controlled call into a more privileged or differently metered runtime path, breaking the invariant that no signed user can turn a normal call into a privileged or underpriced state change, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries
- Exploit idea: converts a user-controlled call into a more privileged or differently metered runtime path
- Invariant to test: no signed user can turn a normal call into a privileged or underpriced state change
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary

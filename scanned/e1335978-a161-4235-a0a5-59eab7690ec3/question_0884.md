# Q884: claim-path state divergence via proxy proxy multisig as on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Polkadot Relay runtime and control repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries so that `impl pallet_staking::Config` converts a user-controlled call into a more privileged or differently metered runtime path, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_staking::Config`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries
- Exploit idea: converts a user-controlled call into a more privileged or differently metered runtime path
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary

# Q1028: pool-versus-staking split via proxy proxy multisig as on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Kusama Relay runtime and control nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions so that `impl pallet_rc_migrator::Config` obtains a second payout, claim, or withdrawal after a first transition partially succeeded, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to high - network-wide halt or stuck critical queue?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions
- Exploit idea: obtains a second payout, claim, or withdrawal after a first transition partially succeeded
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: High - network-wide halt or stuck critical queue
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears

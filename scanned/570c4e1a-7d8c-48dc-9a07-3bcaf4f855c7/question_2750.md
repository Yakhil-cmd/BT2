# Q2750: identity refund double-count via proxy proxy utility batch on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around identity-changing calls on People Polkadot identity config and control locations or treasury-routing state that receive slashed identity deposits so that `impl pallet_identity::Config` creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated, breaking the invariant that identity-related deposits must be debited, refunded, or slashed exactly once, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `impl pallet_identity::Config`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around identity-changing calls
- Attacker controls: locations or treasury-routing state that receive slashed identity deposits
- Exploit idea: creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated
- Invariant to test: identity-related deposits must be debited, refunded, or slashed exactly once
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries

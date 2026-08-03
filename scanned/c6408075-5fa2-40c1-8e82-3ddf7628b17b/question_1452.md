# Q1452: fee-conversion inconsistency via nominationpools join bond extra on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Asset Hub Polkadot runtime and control liquidity ratios, exact-in/exact-out swap parameters, and fee-paying asset selection so that `impl pallet_assets::Config` makes proxy, XCM, or batched execution bypass the intended restrictions of the underlying asset or staking path, breaking the invariant that no user-controlled asset path may create unbacked issuance or release more value than it debits, and leading to critical - unauthorized withdrawal, unlock, or treasury-affecting transfer?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `impl pallet_assets::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: liquidity ratios, exact-in/exact-out swap parameters, and fee-paying asset selection
- Exploit idea: makes proxy, XCM, or batched execution bypass the intended restrictions of the underlying asset or staking path
- Invariant to test: no user-controlled asset path may create unbacked issuance or release more value than it debits
- Expected Immunefi impact: Critical - unauthorized withdrawal, unlock, or treasury-affecting transfer
- Fast validation: stateful fuzz test over asset kind, fee asset, approval, and pool-state permutations

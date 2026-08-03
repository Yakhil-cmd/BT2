# Q1683: proxy-batched asset escape via nominationpools join bond extra on Asset Hub Kusama runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Asset Hub Kusama runtime and control liquidity ratios, exact-in/exact-out swap parameters, and fee-paying asset selection so that `impl pallet_asset_tx_payment::Config` makes two asset subsystems disagree about which pallet owns, mints, burns, or escrows the same economic unit, breaking the invariant that batching and proxying must not widen permissions on asset movement or treasury-affecting flows, and leading to critical - direct loss of funds or unbacked asset issuance?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: liquidity ratios, exact-in/exact-out swap parameters, and fee-paying asset selection
- Exploit idea: makes two asset subsystems disagree about which pallet owns, mints, burns, or escrows the same economic unit
- Invariant to test: batching and proxying must not widen permissions on asset movement or treasury-affecting flows
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset issuance
- Fast validation: stateful fuzz test over asset kind, fee asset, approval, and pool-state permutations

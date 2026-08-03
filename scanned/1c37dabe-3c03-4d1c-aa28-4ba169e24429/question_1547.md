# Q1547: proxy-batched asset escape via pallet remote proxy remote on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `pallet_remote_proxy::{remote_proxy, remote_proxy_with_registered_proof}` on Asset Hub Polkadot runtime and control liquidity ratios, exact-in/exact-out swap parameters, and fee-paying asset selection so that `impl pallet_assets::Config` creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem, breaking the invariant that approvals, proofs, and queued calls must expire or fail once their authorizing state changes, and leading to high - severe availability loss on a critical asset-transfer or xcm path?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `impl pallet_assets::Config`
- Entrypoint: `pallet_remote_proxy::{remote_proxy, remote_proxy_with_registered_proof}`
- Attacker controls: liquidity ratios, exact-in/exact-out swap parameters, and fee-paying asset selection
- Exploit idea: creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem
- Invariant to test: approvals, proofs, and queued calls must expire or fail once their authorizing state changes
- Expected Immunefi impact: High - severe availability loss on a critical asset-transfer or XCM path
- Fast validation: runtime integration test that compares debit, credit, issuance, and beneficiary state across all touched pallets

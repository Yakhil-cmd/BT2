# Q888: double-withdraw edge via xcmpallet execute send limited on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `XcmPallet::{execute, send, limited_reserve_transfer_assets, teleport_assets}` on Polkadot Relay runtime and control fee-paying and fee-waived paths that touch the same balance, hold, reserve, or unlock bookkeeping so that `impl pallet_nomination_pools::Config` obtains a second payout, claim, or withdrawal after a first transition partially succeeded, breaking the invariant that unlocking state, holds, and reserves must stay consistent across all touched pallets, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `XcmPallet::{execute, send, limited_reserve_transfer_assets, teleport_assets}`
- Attacker controls: fee-paying and fee-waived paths that touch the same balance, hold, reserve, or unlock bookkeeping
- Exploit idea: obtains a second payout, claim, or withdrawal after a first transition partially succeeded
- Invariant to test: unlocking state, holds, and reserves must stay consistent across all touched pallets
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

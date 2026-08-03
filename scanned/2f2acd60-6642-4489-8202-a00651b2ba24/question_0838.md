# Q838: pool-versus-staking split via xcmpallet execute send limited on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `XcmPallet::{execute, send, limited_reserve_transfer_assets, teleport_assets}` on Polkadot Relay runtime and control repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries so that `impl pallet_nomination_pools::Config` makes issuance, rewards, or held and reserved balances drift from what users can actually withdraw, breaking the invariant that user-controlled batching must not bypass staking, pool, claim, or proxy restrictions, and leading to high - network-wide halt or stuck critical queue?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `XcmPallet::{execute, send, limited_reserve_transfer_assets, teleport_assets}`
- Attacker controls: repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries
- Exploit idea: makes issuance, rewards, or held and reserved balances drift from what users can actually withdraw
- Invariant to test: user-controlled batching must not bypass staking, pool, claim, or proxy restrictions
- Expected Immunefi impact: High - network-wide halt or stuck critical queue
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

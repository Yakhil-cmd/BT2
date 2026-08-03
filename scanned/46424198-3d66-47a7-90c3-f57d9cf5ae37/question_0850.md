# Q850: unlock-ordering mismatch via crowdloan contribute withdraw on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Crowdloan::{contribute, withdraw}` on Polkadot Relay runtime and control crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries so that `impl pallet_staking::Config` forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_staking::Config`
- Entrypoint: `Crowdloan::{contribute, withdraw}`
- Attacker controls: crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries
- Exploit idea: forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state

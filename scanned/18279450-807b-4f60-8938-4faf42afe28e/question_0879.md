# Q879: proxy-batch privilege widening via crowdloan contribute withdraw on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Crowdloan::{contribute, withdraw}` on Polkadot Relay runtime and control nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` makes issuance, rewards, or held and reserved balances drift from what users can actually withdraw, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to high - network-wide halt or stuck critical queue?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `Crowdloan::{contribute, withdraw}`
- Attacker controls: nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions
- Exploit idea: makes issuance, rewards, or held and reserved balances drift from what users can actually withdraw
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: High - network-wide halt or stuck critical queue
- Fast validation: stateful fuzz test comparing pre and post balances, holds, reserves, and points

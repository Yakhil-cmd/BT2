# Q2856: approval-settlement split via polkadotxcm send transfer assets on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path on People Polkadot asset config and control asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user so that `impl pallet_asset_tx_payment::Config` makes asset-fee charging and final credit resolution disagree about which asset or amount was paid, breaking the invariant that asset-based fee payment must not debit less value than the chain settles or executes against, and leading to high - undercharged execution on a critical asset-moving path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path
- Attacker controls: asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user
- Exploit idea: makes asset-fee charging and final credit resolution disagree about which asset or amount was paid
- Invariant to test: asset-based fee payment must not debit less value than the chain settles or executes against
- Expected Immunefi impact: High - undercharged execution on a critical asset-moving path
- Fast validation: runtime integration test comparing debits, credits, and fee sink across fee-paid asset transfers

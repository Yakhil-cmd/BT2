# Q2857: reserve-asset confusion via polkadotxcm send transfer assets on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path on People Polkadot asset config and control combined fee-payment and asset-transfer flows that touch both local balances and asset balances so that `impl pallet_asset_tx_payment::Config` lets a user spend, approve, or move an asset under one identity while settlement happens under another, breaking the invariant that asset-based fee payment must not debit less value than the chain settles or executes against, and leading to critical - permanent freeze or misclassification of an asset balance?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path
- Attacker controls: combined fee-payment and asset-transfer flows that touch both local balances and asset balances
- Exploit idea: lets a user spend, approve, or move an asset under one identity while settlement happens under another
- Invariant to test: asset-based fee payment must not debit less value than the chain settles or executes against
- Expected Immunefi impact: Critical - permanent freeze or misclassification of an asset balance
- Fast validation: xcm-emulator test for reserve classification and settlement of the HOLLAR-like asset path

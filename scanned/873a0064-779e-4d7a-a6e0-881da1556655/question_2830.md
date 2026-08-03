# Q2830: reserve-asset confusion via assettxpayment signed fee paying on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `AssetTxPayment` signed fee-paying path on People Polkadot asset config and control combined fee-payment and asset-transfer flows that touch both local balances and asset balances so that `impl pallet_asset_tx_payment::Config` lets a user spend, approve, or move an asset under one identity while settlement happens under another, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to critical - permanent freeze or misclassification of an asset balance?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `AssetTxPayment` signed fee-paying path
- Attacker controls: combined fee-payment and asset-transfer flows that touch both local balances and asset balances
- Exploit idea: lets a user spend, approve, or move an asset under one identity while settlement happens under another
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: Critical - permanent freeze or misclassification of an asset balance
- Fast validation: xcm-emulator test for reserve classification and settlement of the HOLLAR-like asset path

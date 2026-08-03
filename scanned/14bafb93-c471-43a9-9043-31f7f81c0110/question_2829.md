# Q2829: approval-settlement split via assettxpayment signed fee paying on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `AssetTxPayment` signed fee-paying path on People Polkadot asset config and control asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user so that `impl pallet_asset_tx_payment::Config` makes asset-fee charging and final credit resolution disagree about which asset or amount was paid, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to high - undercharged execution on a critical asset-moving path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `AssetTxPayment` signed fee-paying path
- Attacker controls: asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user
- Exploit idea: makes asset-fee charging and final credit resolution disagree about which asset or amount was paid
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: High - undercharged execution on a critical asset-moving path
- Fast validation: runtime integration test comparing debits, credits, and fee sink across fee-paid asset transfers

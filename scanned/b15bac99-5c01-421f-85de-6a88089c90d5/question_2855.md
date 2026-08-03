# Q2855: asset-fee mismatch via assettxpayment signed fee paying on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `AssetTxPayment` signed fee-paying path on People Polkadot asset config and control XCM asset movements where reserve matching and local asset ownership can disagree so that `impl pallet_asset_tx_payment::Config` lets a user spend, approve, or move an asset under one identity while settlement happens under another, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to critical - direct loss of funds or unbacked asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `AssetTxPayment` signed fee-paying path
- Attacker controls: XCM asset movements where reserve matching and local asset ownership can disagree
- Exploit idea: lets a user spend, approve, or move an asset under one identity while settlement happens under another
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset movement
- Fast validation: runtime integration test comparing debits, credits, and fee sink across fee-paid asset transfers

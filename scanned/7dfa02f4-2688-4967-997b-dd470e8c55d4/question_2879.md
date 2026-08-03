# Q2879: asset-fee mismatch via assettxpayment signed fee paying on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `AssetTxPayment` signed fee-paying path on People Polkadot asset config and control XCM asset movements where reserve matching and local asset ownership can disagree so that `impl pallet_asset_tx_payment::Config` makes asset-fee charging and final credit resolution disagree about which asset or amount was paid, breaking the invariant that asset-based fee payment must not debit less value than the chain settles or executes against, and leading to high - undercharged execution on a critical asset-moving path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `AssetTxPayment` signed fee-paying path
- Attacker controls: XCM asset movements where reserve matching and local asset ownership can disagree
- Exploit idea: makes asset-fee charging and final credit resolution disagree about which asset or amount was paid
- Invariant to test: asset-based fee payment must not debit less value than the chain settles or executes against
- Expected Immunefi impact: High - undercharged execution on a critical asset-moving path
- Fast validation: xcm-emulator test for reserve classification and settlement of the HOLLAR-like asset path

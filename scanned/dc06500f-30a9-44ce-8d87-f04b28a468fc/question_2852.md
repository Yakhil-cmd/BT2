# Q2852: asset-fee mismatch via assets transfer transfer approved on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `Assets::{transfer, transfer_approved}` on People Polkadot asset config and control XCM asset movements where reserve matching and local asset ownership can disagree so that `impl pallet_asset_tx_payment::Config` makes asset-fee charging and final credit resolution disagree about which asset or amount was paid, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to high - undercharged execution on a critical asset-moving path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `Assets::{transfer, transfer_approved}`
- Attacker controls: XCM asset movements where reserve matching and local asset ownership can disagree
- Exploit idea: makes asset-fee charging and final credit resolution disagree about which asset or amount was paid
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: High - undercharged execution on a critical asset-moving path
- Fast validation: xcm-emulator test for reserve classification and settlement of the HOLLAR-like asset path

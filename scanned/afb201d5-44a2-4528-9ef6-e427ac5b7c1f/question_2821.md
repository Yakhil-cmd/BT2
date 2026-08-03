# Q2821: reserve-asset confusion via assettxpayment signed fee paying on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `AssetTxPayment` signed fee-paying path on People Polkadot asset config and control asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user so that `impl pallet_assets::Config` causes `HollarFromHydration`, asset conversion, and transfer logic to classify the same asset differently across the path, breaking the invariant that asset-based fee payment must not debit less value than the chain settles or executes against, and leading to high - undercharged execution on a critical asset-moving path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_assets::Config`
- Entrypoint: `AssetTxPayment` signed fee-paying path
- Attacker controls: asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user
- Exploit idea: causes `HollarFromHydration`, asset conversion, and transfer logic to classify the same asset differently across the path
- Invariant to test: asset-based fee payment must not debit less value than the chain settles or executes against
- Expected Immunefi impact: High - undercharged execution on a critical asset-moving path
- Fast validation: xcm-emulator test for reserve classification and settlement of the HOLLAR-like asset path

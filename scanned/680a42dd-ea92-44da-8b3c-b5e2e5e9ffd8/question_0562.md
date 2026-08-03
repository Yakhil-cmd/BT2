# Q562: waived-execution bypass via xcmpallet limited reserve transfer on Polkadot Relay XCM

## Question
Can an unprivileged attacker enter through `XcmPallet::limited_reserve_transfer_assets` on Polkadot Relay XCM and control a location that can be interpreted differently across aliasing, account conversion, and asset transacting code so that `SovereignAccountOf` makes pre-dispatch fee estimation and final withdrawal disagree on the effective asset, payer, or beneficiary, breaking the invariant that delivery, execution, and refund accounting must not let a user extract more value than was actually debited, and leading to critical - unbacked asset mint, unlock, or withdrawal?

## Target
- File/function: `relay/polkadot/src/xcm_config.rs` :: `SovereignAccountOf`
- Entrypoint: `XcmPallet::limited_reserve_transfer_assets`
- Attacker controls: a location that can be interpreted differently across aliasing, account conversion, and asset transacting code
- Exploit idea: makes pre-dispatch fee estimation and final withdrawal disagree on the effective asset, payer, or beneficiary
- Invariant to test: delivery, execution, and refund accounting must not let a user extract more value than was actually debited
- Expected Immunefi impact: Critical - unbacked asset mint, unlock, or withdrawal
- Fast validation: xcm-emulator test that drives the exact signed or source-chain user path and asserts final origin plus asset balances

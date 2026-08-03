# Q1512: cross-asset accounting split via proxy proxy multisig as on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Asset Hub Polkadot runtime and control nested proxy, batch, multisig, and XCM composition around asset-moving calls so that `impl pallet_asset_tx_payment::Config` makes proxy, XCM, or batched execution bypass the intended restrictions of the underlying asset or staking path, breaking the invariant that fees, refunds, and swapped amounts must reconcile with the final debits and credits, and leading to high - severe availability loss on a critical asset-transfer or xcm path?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: nested proxy, batch, multisig, and XCM composition around asset-moving calls
- Exploit idea: makes proxy, XCM, or batched execution bypass the intended restrictions of the underlying asset or staking path
- Invariant to test: fees, refunds, and swapped amounts must reconcile with the final debits and credits
- Expected Immunefi impact: High - severe availability loss on a critical asset-transfer or XCM path
- Fast validation: xcm-emulator test that drives the exact reserve, teleport, or exporter flow and asserts no value drift

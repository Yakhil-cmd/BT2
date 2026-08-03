# Q3778: remote-payout beneficiary split via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control asset kinds whose local and remote locations can be reanchored in multiple ways so that `fee_asset / ConstantKsmFee` reuses query, response, or timeout state so the same remote payout can be treated as fresh more than once, breaking the invariant that one treasury payout must map to one remote transfer and one final beneficiary, and leading to critical - direct loss of funds or duplicated treasury payout?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `fee_asset / ConstantKsmFee`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: asset kinds whose local and remote locations can be reanchored in multiple ways
- Exploit idea: reuses query, response, or timeout state so the same remote payout can be treated as fresh more than once
- Invariant to test: one treasury payout must map to one remote transfer and one final beneficiary
- Expected Immunefi impact: Critical - direct loss of funds or duplicated treasury payout
- Fast validation: stateful fuzz test over asset location, beneficiary conversion, and payment-status replay

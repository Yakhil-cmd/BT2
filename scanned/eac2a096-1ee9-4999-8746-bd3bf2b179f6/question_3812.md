# Q3812: fee-asset settlement mismatch via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper so that `TransferOverXcm::from_on_remote` reuses query, response, or timeout state so the same remote payout can be treated as fresh more than once, breaking the invariant that one treasury payout must map to one remote transfer and one final beneficiary, and leading to critical - permanent freeze or misdelivery of treasury funds?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::from_on_remote`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper
- Exploit idea: reuses query, response, or timeout state so the same remote payout can be treated as fresh more than once
- Invariant to test: one treasury payout must map to one remote transfer and one final beneficiary
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of treasury funds
- Fast validation: stateful fuzz test over asset location, beneficiary conversion, and payment-status replay

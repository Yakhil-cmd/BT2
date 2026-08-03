# Q3771: remote-transfer success drift via encointertreasuries signed payout or on Encointer remote treasury payout hel

## Question
Can an unprivileged attacker enter through `EncointerTreasuries` signed payout or transfer path on Encointer remote treasury payout helper and control beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper so that `TransferOverXcm::transfer` reuses query, response, or timeout state so the same remote payout can be treated as fresh more than once, breaking the invariant that one treasury payout must map to one remote transfer and one final beneficiary, and leading to high - stuck remote payout queue with concrete fund impact?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::transfer`
- Entrypoint: `EncointerTreasuries` signed payout or transfer path
- Attacker controls: beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper
- Exploit idea: reuses query, response, or timeout state so the same remote payout can be treated as fresh more than once
- Invariant to test: one treasury payout must map to one remote transfer and one final beneficiary
- Expected Immunefi impact: High - stuck remote payout queue with concrete fund impact
- Fast validation: integration test that checks local success, remote execution result, and replay resistance together

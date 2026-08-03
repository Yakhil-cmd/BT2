# Q3772: fee-asset settlement mismatch via encointertreasuries signed payout or on Encointer remote treasury payout hel

## Question
Can an unprivileged attacker enter through `EncointerTreasuries` signed payout or transfer path on Encointer remote treasury payout helper and control beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper so that `TransferOverXcm::transfer` makes fee charging and remote settlement use different asset identities or amounts, breaking the invariant that one treasury payout must map to one remote transfer and one final beneficiary, and leading to critical - direct loss of funds or duplicated treasury payout?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::transfer`
- Entrypoint: `EncointerTreasuries` signed payout or transfer path
- Attacker controls: beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper
- Exploit idea: makes fee charging and remote settlement use different asset identities or amounts
- Invariant to test: one treasury payout must map to one remote transfer and one final beneficiary
- Expected Immunefi impact: Critical - direct loss of funds or duplicated treasury payout
- Fast validation: integration test that checks local success, remote execution result, and replay resistance together

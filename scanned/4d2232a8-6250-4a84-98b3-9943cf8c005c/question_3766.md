# Q3766: remote-payout beneficiary split via encointertreasuries signed payout or on Encointer remote treasury payout h

## Question
Can an unprivileged attacker enter through `EncointerTreasuries` signed payout or transfer path on Encointer remote treasury payout helper and control asset kinds whose local and remote locations can be reanchored in multiple ways so that `TransferOverXcm::transfer` lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value, breaking the invariant that one treasury payout must map to one remote transfer and one final beneficiary, and leading to critical - permanent freeze or misdelivery of treasury funds?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::transfer`
- Entrypoint: `EncointerTreasuries` signed payout or transfer path
- Attacker controls: asset kinds whose local and remote locations can be reanchored in multiple ways
- Exploit idea: lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value
- Invariant to test: one treasury payout must map to one remote transfer and one final beneficiary
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of treasury funds
- Fast validation: stateful fuzz test over asset location, beneficiary conversion, and payment-status replay

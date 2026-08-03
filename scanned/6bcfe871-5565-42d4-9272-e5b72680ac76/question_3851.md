# Q3851: remote-transfer success drift via encointertreasuries signed payout or on Encointer remote treasury payout hel

## Question
Can an unprivileged attacker enter through `EncointerTreasuries` signed payout or transfer path on Encointer remote treasury payout helper and control query ids, timeout windows, and replayed payment-status checks around the same remote transfer so that `TransferOverXcm::get_remote_transfer_xcm` lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value, breaking the invariant that local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for, and leading to critical - permanent freeze or misdelivery of treasury funds?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::get_remote_transfer_xcm`
- Entrypoint: `EncointerTreasuries` signed payout or transfer path
- Attacker controls: query ids, timeout windows, and replayed payment-status checks around the same remote transfer
- Exploit idea: lets a caller observe a success state locally while the remote transfer can still be replayed, fail open, or strand value
- Invariant to test: local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of treasury funds
- Fast validation: xcm-emulator test over `get_remote_transfer_xcm`, emitted query state, and final beneficiary accounting

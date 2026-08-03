# Q3822: remote-payout beneficiary split via encointertreasuries signed payout or on Encointer remote treasury payout h

## Question
Can an unprivileged attacker enter through `EncointerTreasuries` signed payout or transfer path on Encointer remote treasury payout helper and control query ids, timeout windows, and replayed payment-status checks around the same remote transfer so that `TransferOverXcm::from_on_remote` reuses query, response, or timeout state so the same remote payout can be treated as fresh more than once, breaking the invariant that local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for, and leading to critical - permanent freeze or misdelivery of treasury funds?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `TransferOverXcm::from_on_remote`
- Entrypoint: `EncointerTreasuries` signed payout or transfer path
- Attacker controls: query ids, timeout windows, and replayed payment-status checks around the same remote transfer
- Exploit idea: reuses query, response, or timeout state so the same remote payout can be treated as fresh more than once
- Invariant to test: local success state must never be reachable unless the remote transfer is uniquely bound and fully accounted for
- Expected Immunefi impact: Critical - permanent freeze or misdelivery of treasury funds
- Fast validation: integration test that checks local success, remote execution result, and replay resistance together

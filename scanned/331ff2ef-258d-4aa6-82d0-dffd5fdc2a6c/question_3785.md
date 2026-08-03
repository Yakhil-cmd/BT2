# Q3785: query-state replay on payout via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper so that `fee_asset / ConstantKsmFee` makes fee charging and remote settlement use different asset identities or amounts, breaking the invariant that query and response state must not make a remote payout replayable or permanently unclaimable, and leading to critical - direct loss of funds or duplicated treasury payout?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `fee_asset / ConstantKsmFee`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: beneficiary conversion, fee-asset selection, and asset locations passed into the remote transfer helper
- Exploit idea: makes fee charging and remote settlement use different asset identities or amounts
- Invariant to test: query and response state must not make a remote payout replayable or permanently unclaimable
- Expected Immunefi impact: Critical - direct loss of funds or duplicated treasury payout
- Fast validation: integration test that checks local success, remote execution result, and replay resistance together

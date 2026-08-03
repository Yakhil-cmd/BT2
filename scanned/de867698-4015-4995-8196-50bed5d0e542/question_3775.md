# Q3775: remote-transfer success drift via proxy proxy utility batch on Encointer remote treasury payout helper

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout on Encointer remote treasury payout helper and control batched treasury payouts that reuse the same source account and remote execution fee assumptions so that `fee_asset / ConstantKsmFee` makes fee charging and remote settlement use different asset identities or amounts, breaking the invariant that fee assets and transferred assets must reconcile exactly with the remote message that is emitted, and leading to critical - direct loss of funds or duplicated treasury payout?

## Target
- File/function: `system-parachains/encointer/src/treasuries_xcm_payout.rs` :: `fee_asset / ConstantKsmFee`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around a remote treasury payout
- Attacker controls: batched treasury payouts that reuse the same source account and remote execution fee assumptions
- Exploit idea: makes fee charging and remote settlement use different asset identities or amounts
- Invariant to test: fee assets and transferred assets must reconcile exactly with the remote message that is emitted
- Expected Immunefi impact: Critical - direct loss of funds or duplicated treasury payout
- Fast validation: stateful fuzz test over asset location, beneficiary conversion, and payment-status replay

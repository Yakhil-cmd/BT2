# Q556: message-export route confusion via xcmpallet send on Polkadot Relay XCM

## Question
Can an unprivileged attacker enter through `XcmPallet::send` on Polkadot Relay XCM and control an execution path that alternates between paid execution, explicitly unpaid execution, and refund handling so that `FeeManager / Aliasers` makes pre-dispatch fee estimation and final withdrawal disagree on the effective asset, payer, or beneficiary, breaking the invariant that location-to-account conversion must stay injective enough for all accepted user and XCM flows, and leading to critical - permanent freeze or loss of bridged or transferred user funds?

## Target
- File/function: `relay/polkadot/src/xcm_config.rs` :: `FeeManager / Aliasers`
- Entrypoint: `XcmPallet::send`
- Attacker controls: an execution path that alternates between paid execution, explicitly unpaid execution, and refund handling
- Exploit idea: makes pre-dispatch fee estimation and final withdrawal disagree on the effective asset, payer, or beneficiary
- Invariant to test: location-to-account conversion must stay injective enough for all accepted user and XCM flows
- Expected Immunefi impact: Critical - permanent freeze or loss of bridged or transferred user funds
- Fast validation: targeted integration test proving whether the message can reach export, teleport, reserve, or transact paths it should never reach

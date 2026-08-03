# Q2370: relayer-payout replay via bridgerelayers signed reward claim on Bridge reward payment logic

## Question
Can an unprivileged attacker enter through `BridgeRelayers` signed reward-claim or beneficiary-selection path on Bridge reward payment logic and control reward kind, beneficiary type, and beneficiary location encoding around payout finalization so that `BridgeRewardBeneficiaries` routes a relayer reward to a different beneficiary type or destination than the runtime intended, breaking the invariant that one bridge reward must map to one beneficiary and one non-replayable payout result, and leading to critical - permanent freeze of earned bridge rewards?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_common_config.rs` :: `BridgeRewardBeneficiaries`
- Entrypoint: `BridgeRelayers` signed reward-claim or beneficiary-selection path
- Attacker controls: reward kind, beneficiary type, and beneficiary location encoding around payout finalization
- Exploit idea: routes a relayer reward to a different beneficiary type or destination than the runtime intended
- Invariant to test: one bridge reward must map to one beneficiary and one non-replayable payout result
- Expected Immunefi impact: Critical - permanent freeze of earned bridge rewards
- Fast validation: integration test over reward payout with each beneficiary type and versioned location variant

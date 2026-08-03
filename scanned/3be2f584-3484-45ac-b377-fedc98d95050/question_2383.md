# Q2383: reward-beneficiary mismatch via bridgerelayers signed reward claim on Bridge reward payment logic

## Question
Can an unprivileged attacker enter through `BridgeRelayers` signed reward-claim or beneficiary-selection path on Bridge reward payment logic and control reward kind, beneficiary type, and beneficiary location encoding around payout finalization so that `BridgeRewardBeneficiaries` causes staking, slashability, and reward settlement state to disagree about whether a relayer action was finalized, breaking the invariant that beneficiary-type conversion must never leak rewards to attacker-chosen locations or incompatible payout paths, and leading to high - payout-path corruption with concrete bridge-operational impact?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_common_config.rs` :: `BridgeRewardBeneficiaries`
- Entrypoint: `BridgeRelayers` signed reward-claim or beneficiary-selection path
- Attacker controls: reward kind, beneficiary type, and beneficiary location encoding around payout finalization
- Exploit idea: causes staking, slashability, and reward settlement state to disagree about whether a relayer action was finalized
- Invariant to test: beneficiary-type conversion must never leak rewards to attacker-chosen locations or incompatible payout paths
- Expected Immunefi impact: High - payout-path corruption with concrete bridge-operational impact
- Fast validation: integration test over reward payout with each beneficiary type and versioned location variant

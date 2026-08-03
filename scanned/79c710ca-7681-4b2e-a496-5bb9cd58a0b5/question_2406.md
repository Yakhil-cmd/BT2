# Q2406: relayer-payout replay via snowbridge settlement path that on Bridge reward payment logic

## Question
Can an unprivileged attacker enter through `Snowbridge settlement path that triggers a relayer reward payout` on Bridge reward payment logic and control reward kind, beneficiary type, and beneficiary location encoding around payout finalization so that `BridgeRewardBeneficiaries` causes staking, slashability, and reward settlement state to disagree about whether a relayer action was finalized, breaking the invariant that one bridge reward must map to one beneficiary and one non-replayable payout result, and leading to critical - direct theft or misdirection of bridge relayer rewards?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_common_config.rs` :: `BridgeRewardBeneficiaries`
- Entrypoint: `Snowbridge settlement path that triggers a relayer reward payout`
- Attacker controls: reward kind, beneficiary type, and beneficiary location encoding around payout finalization
- Exploit idea: causes staking, slashability, and reward settlement state to disagree about whether a relayer action was finalized
- Invariant to test: one bridge reward must map to one beneficiary and one non-replayable payout result
- Expected Immunefi impact: Critical - direct theft or misdirection of bridge relayer rewards
- Fast validation: integration test over reward payout with each beneficiary type and versioned location variant

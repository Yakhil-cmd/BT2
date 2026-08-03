# Q2411: stake-reward desync via bridgerelayers signed reward claim on Bridge reward payment logic

## Question
Can an unprivileged attacker enter through `BridgeRelayers` signed reward-claim or beneficiary-selection path on Bridge reward payment logic and control stake-lease timing and reward-claim ordering for the same relayer account so that `BridgeRewardPayer::pay_reward` causes staking, slashability, and reward settlement state to disagree about whether a relayer action was finalized, breaking the invariant that one bridge reward must map to one beneficiary and one non-replayable payout result, and leading to critical - direct theft or misdirection of bridge relayer rewards?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_common_config.rs` :: `BridgeRewardPayer::pay_reward`
- Entrypoint: `BridgeRelayers` signed reward-claim or beneficiary-selection path
- Attacker controls: stake-lease timing and reward-claim ordering for the same relayer account
- Exploit idea: causes staking, slashability, and reward settlement state to disagree about whether a relayer action was finalized
- Invariant to test: one bridge reward must map to one beneficiary and one non-replayable payout result
- Expected Immunefi impact: Critical - direct theft or misdirection of bridge relayer rewards
- Fast validation: integration test over reward payout with each beneficiary type and versioned location variant

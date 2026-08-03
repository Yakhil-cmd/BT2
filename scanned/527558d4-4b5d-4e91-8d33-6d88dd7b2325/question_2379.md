# Q2379: relayer-payout replay via bridgerelayers signed reward claim on Bridge reward payment logic

## Question
Can an unprivileged attacker enter through `BridgeRelayers` signed reward-claim or beneficiary-selection path on Bridge reward payment logic and control versioned beneficiary locations that may decode differently than the payout path expects so that `BridgeRewardPayer::pay_reward` makes a reward claim succeed locally while the actual payout stays replayable, misdirected, or permanently unclaimable, breaking the invariant that beneficiary-type conversion must never leak rewards to attacker-chosen locations or incompatible payout paths, and leading to critical - direct theft or misdirection of bridge relayer rewards?

## Target
- File/function: `system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_common_config.rs` :: `BridgeRewardPayer::pay_reward`
- Entrypoint: `BridgeRelayers` signed reward-claim or beneficiary-selection path
- Attacker controls: versioned beneficiary locations that may decode differently than the payout path expects
- Exploit idea: makes a reward claim succeed locally while the actual payout stays replayable, misdirected, or permanently unclaimable
- Invariant to test: beneficiary-type conversion must never leak rewards to attacker-chosen locations or incompatible payout paths
- Expected Immunefi impact: Critical - direct theft or misdirection of bridge relayer rewards
- Fast validation: integration test over reward payout with each beneficiary type and versioned location variant

### Title
Stake account `Split` during the reward-distribution window triggers a deterministic `assert_eq!` panic in `build_updated_stake_reward`, causing an epoch-boundary consensus halt - (File: runtime/src/bank/partitioned_epoch_rewards/distribution.rs)

### Summary
The specific "reward redirected to a different authority" scenario described in the question is not exploitable: `build_updated_stake_reward` always looks up the reward's target by the fixed `stake_pubkey` recorded during the calculation phase, and stake-program signer checks prevent an attacker from mutating accounts they do not control, so `Authorize` on the attacker's own account never moves reward lamports to a different pubkey. However, investigating the same "mutate stake account inside the distribution window" scenario surfaced a real, related bug: calling `Split` on one's own scheduled stake account between reward calculation and its assigned distribution block deterministically panics the validator via an `assert_eq!` in `build_updated_stake_reward`, when the `relax_post_exec_min_balance_check` feature is not active.

### Finding Description
`store_stake_accounts_in_partition` and `build_updated_stake_reward` in `runtime/src/bank/partitioned_epoch_rewards/distribution.rs` credit rewards by reading the *current* (live) stake account from `stakes_cache_accounts` at distribution time, not a frozen snapshot from the rewarded epoch: [1](#0-0) 

Nothing in `runtime/src/bank/partitioned_epoch_rewards/mod.rs` prevents ordinary stake-program instructions from executing against a stake account while `EpochRewardStatus::Active` is set; `get_reward_interval()` is only referenced from unit tests, never used to gate transaction processing: [2](#0-1) 

If `adjust_delegations_for_rent` (gated by feature `relax_post_exec_min_balance_check`) is inactive, the code asserts that the current stake delegation plus the calculated reward exactly equals the pre-computed new delegation: [3](#0-2) 

An attacker can submit a `Split` instruction against their own stake account (a legitimate, signer-authorized operation on an account they own) after reward calculation but before their partition's distribution block. `Split` reduces the source account's `delegation.stake` and lamports while keeping it as a valid `StakeStateV2::Stake` entry (so it still appears in `stakes_cache_accounts`, unlike a full deactivation/close). At distribution time, `stake.delegation.stake` (now reduced) plus `partitioned_stake_reward.inflation.stake_reward` (computed against the pre-split, larger balance) no longer equals `new_stake.delegation.stake` (the pre-split expected value baked into `PartitionedStakeReward` during calculation), and the `assert_eq!` panics. This is an unconditional Rust panic, not a recoverable `Result::Err`, and it executes deterministically for every node processing the block, causing a consensus-wide halt.

### Impact Explanation
This qualifies as an "epoch-boundary halt": a normal, unprivileged validator/staker can crash every node processing a specific slot purely by splitting their own delegated stake account during the (unguarded) reward-distribution window, when `relax_post_exec_min_balance_check` is not yet active on the cluster. The originally hypothesized theft/redirection of rewards to a different authority is not achievable, since crediting is strictly keyed by `stake_pubkey` and the stake program's own signer checks prevent unauthorized mutation of victim accounts.

### Likelihood Explanation
Feasible whenever (a) a stake account is scheduled into a later reward partition, (b) the `EpochRewards` sysvar is active, and (c) `relax_post_exec_min_balance_check` is not activated (e.g., prior to its cluster-wide activation, or on any testnet/devnet still running with it disabled). No special privileges are needed - only a normal funded stake account and one `Split` transaction sent within the multi-block distribution window, which can span many slots on large validator sets. This is deterministically reproducible.

### Recommendation
Replace the `assert_eq!` in `build_updated_stake_reward` with a recoverable `DistributionError` variant (mirroring the `AccountNotFound`/`ArithmeticOverflow` handling already in the same function), so a stake-state mismatch caused by intervening `Split`/`Merge`/other stake-program mutations during the distribution window results in the reward being safely burned/logged rather than panicking the bank. Additionally, consider snapshotting/recomputing expected delegation from the live account state (as is already done for the `adjust_delegations_for_rent` branch) unconditionally, rather than relying on an exact equality invariant that any legitimate in-window stake mutation can violate.

### Proof of Concept
```rust
// runtime/src/bank/partitioned_epoch_rewards/distribution.rs (test module)
#[test]
fn test_split_during_distribution_window_panics_without_rent_adjustment() {
    let (genesis_config, _mint_keypair) = create_genesis_config(1_000_000 * LAMPORTS_PER_SOL);
    let bank = Bank::new_for_tests(&genesis_config);
    // adjust_delegations_for_rent = false (feature inactive by default in this test bank)

    let voter_pubkey = Pubkey::new_unique();
    let stake_pubkey = Pubkey::new_unique();
    let rent = bank.rent_collector.rent.clone();
    let rent_exempt_reserve = rent.minimum_balance(StakeStateV2::size_of());

    // Original delegation used during reward *calculation* phase.
    let original_stake_amount = 10 * LAMPORTS_PER_SOL;
    let stake_reward = 1_000_000;
    let new_stake = Stake {
        delegation: Delegation {
            voter_pubkey,
            stake: original_stake_amount + stake_reward, // expected post-reward delegation
            ..Delegation::default()
        },
        credits_observed: 100,
    };
    let partitioned_stake_reward = PartitionedStakeReward {
        stake_pubkey,
        inflation: InflationReward {
            stake: new_stake,
            stake_reward,
            commission_bps: None,
        },
        block_reward: 0,
    };

    // Populate the account as it existed at calculation time.
    let mut stake_account = AccountSharedData::new(
        rent_exempt_reserve + original_stake_amount,
        StakeStateV2::size_of(),
        &solana_stake_interface::program::id(),
    );
    stake_account
        .set_state(&StakeStateV2::Stake(
            Meta::default(),
            Stake {
                delegation: Delegation {
                    voter_pubkey,
                    stake: original_stake_amount,
                    ..Delegation::default()
                },
                credits_observed: 100,
            },
            StakeFlags::default(),
        ))
        .unwrap();
    bank.store_account(&stake_pubkey, &stake_account);

    // Simulate attacker's `Split` executed before this partition's distribution block:
    // half the stake/lamports are moved out, reducing the source account's delegation.
    let split_amount = original_stake_amount / 2;
    let mut post_split_account = stake_account.clone();
    post_split_account.checked_sub_lamports(split_amount).unwrap();
    post_split_account
        .set_state(&StakeStateV2::Stake(
            Meta::default(),
            Stake {
                delegation: Delegation {
                    voter_pubkey,
                    stake: original_stake_amount - split_amount, // reduced!
                    ..Delegation::default()
                },
                credits_observed: 100,
            },
            StakeFlags::default(),
        ))
        .unwrap();
    bank.store_account(&stake_pubkey, &post_split_account);

    let stakes_cache = bank.stakes_cache.stakes();
    let stakes_cache_accounts = stakes_cache.stake_delegations();

    // Expected: this call panics via assert_eq! because the current (post-split)
    // delegation + stake_reward no longer matches the pre-split expected new_stake.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Bank::build_updated_stake_reward(
            bank.epoch + 1,
            &StakeHistory::default(),
            bank.new_warmup_cooldown_rate_epoch(),
            stakes_cache_accounts,
            &partitioned_stake_reward,
            &rent,
            false, // adjust_delegations_for_rent = false
            true,
        )
    }));
    assert!(
        result.is_err(),
        "expected assert_eq! panic due to Split-during-distribution-window mismatch"
    );
}
```
Expected assertion: the call panics (demonstrating the consensus-halting bug) instead of returning a `DistributionError`. Fixing the code to return `Err(DistributionError::StaleDelegation)` (or similar) instead of panicking, and re-running the test expecting `Ok`/`Err` rather than a panic, verifies the recommended fix.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L249-261)
```rust
        let stake_account = stakes_cache_accounts
            .get(&partitioned_stake_reward.stake_pubkey)
            .ok_or(DistributionError::AccountNotFound)?
            .clone();

        let (mut account, stake_state): (AccountSharedData, StakeStateV2) = stake_account.into();
        let StakeStateV2::Stake(meta, stake, flags) = stake_state else {
            // StakesCache only stores accounts where StakeStateV2::delegation().is_some()
            unreachable!(
                "StakesCache entry {:?} failed StakeStateV2 deserialization",
                partitioned_stake_reward.stake_pubkey
            )
        };
```

**File:** runtime/src/bank/partitioned_epoch_rewards/distribution.rs (L284-294)
```rust
        } else {
            let expected_delegation = stake
                .delegation
                .stake
                .saturating_add(partitioned_stake_reward.inflation.stake_reward);
            assert_eq!(
                expected_delegation, new_stake.delegation.stake,
                "stake reward delegation must be consistent with the updated stake account \
                 lamport balance"
            );
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/mod.rs (L542-550)
```rust
    impl Bank {
        /// Return `RewardInterval` enum for current bank
        fn get_reward_interval(&self) -> RewardInterval {
            if matches!(self.epoch_reward_status, EpochRewardStatus::Active(_)) {
                RewardInterval::InsideInterval
            } else {
                RewardInterval::OutsideInterval
            }
        }
```

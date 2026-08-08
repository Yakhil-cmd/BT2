Based on the code, this is not a vulnerability — it describes intended, spec-compliant behavior rather than an attacker-controlled exploit path.

**Key facts from the code:**

1. `redeem_delegation_rewards` computes two independent quantities: the commission *rate* (`commission_bps`) and the commission *destination* (`commission_pubkey`). Only the rate is subject to the one-epoch delay logic via `snapshot_epoch_vote_accounts`/`rewarded_epoch_vote_accounts`. The destination is resolved directly from the live `vote_state` obtained via `distribution_epoch_vote_accounts`: `let commission_pubkey = *vote_state.inflation_rewards_collector().unwrap_or(&vote_pubkey);` [1](#0-0) 

2. `update_commission_collector` requires the vote account's **authorized withdrawer** to sign — an unprivileged staker/delegator cannot invoke it against a victim's vote account they don't control: `verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;` [2](#0-1) 

3. This is SIMD-0232's explicit, intended design: the vote account withdrawer may redirect the vote account's own commission to any valid rent-exempt system account (or the vote account itself), and per code comments/tests this is not delayed the way the commission rate is: [3](#0-2) 

**Why the scenario doesn't hold up as an exploit:**

- The "attacker" in the scenario performs no privileged or unauthorized action at all — the only account-mutating instruction (`UpdateCommissionCollector`) is executed by the **victim's own withdrawer**, which is exactly the party SIMD-0232 authorizes to make that decision. This is not an attacker exploiting a bug; it's the legitimate account owner exercising an intended feature.
- The delegator/staker's own reward share is **not affected** by where the commission portion is routed. `commission_bps` (the split ratio between stake reward and commission) is computed independently of `commission_pubkey`, so changing the collector destination does not siphon lamports away from the delegator's expected reward — it only changes where the vote account's own commission (which was never the delegator's money) ends up.
- There is no reward-exactly-once violation, no double-claim, and no ability for an unprivileged staker to redirect funds without controlling the withdrawer key, as required by the rules ("attacker is unprivileged only... does not control [victim accounts]").

#No vulnerability found for this question.

### Citations

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L701-757)
```rust
        let vote_state = vote_account.vote_state_view();

        // Fetch the voter commission from past epochs to attempt to
        // delay the effect of commission updates by at least one
        // full epoch.
        // When `commission_rate_in_basis_points` is true, use the new field
        // `inflation_rewards_commission_bps`; otherwise use the legacy
        // percentage field and convert to basis points by multiplying by 100.
        let commission_bps = if delay_commission_updates {
            let vote_state_for_commission = snapshot_epoch_vote_accounts
                .and_then(|eva| eva.get(&vote_pubkey))
                .or_else(|| rewarded_epoch_vote_accounts.and_then(|eva| eva.get(&vote_pubkey)))
                .map(|vote_account| vote_account.vote_state_view())
                .unwrap_or(vote_state);
            if commission_rate_in_basis_points {
                vote_state_for_commission.inflation_rewards_commission()
            } else {
                vote_state_for_commission.commission() as u16 * 100
            }
        } else if commission_rate_in_basis_points {
            vote_state.inflation_rewards_commission()
        } else {
            vote_state.commission() as u16 * 100
        };

        match redeem_rewards(
            stake,
            commission_bps,
            DelegatedVoteState::from(vote_state),
            CalculationEnvironment {
                rewarded_epoch,
                point_value,
                stake_history,
                new_rate_activation_epoch,
                commission_rate_in_basis_points,
                adjust_delegations_for_rent,
                use_fixed_point_stake_math,
            },
            reward_calc_tracer,
            ag_epoch_type,
            current_lamports,
            minimum_lamports,
        ) {
            Ok((stake_reward, commission_lamports, stake)) => {
                let inflation = InflationReward {
                    stake,
                    stake_reward,
                    commission_bps: (!custom_commission_collector).then_some(commission_bps),
                };
                let (commission_pubkey, is_vote_account) = if custom_commission_collector {
                    let commission_pubkey = *vote_state
                        .inflation_rewards_collector()
                        .unwrap_or(&vote_pubkey);
                    (commission_pubkey, commission_pubkey == vote_pubkey)
                } else {
                    (vote_pubkey, true)
                };
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L3736-3835)
```rust
    #[test]
    fn test_inflation_rewards_collector() {
        let GenesisConfigInfo {
            mut genesis_config, ..
        } = genesis_utils::create_genesis_config_with_leader(
            1_000_000 * LAMPORTS_PER_SOL,
            &Pubkey::new_unique(),
            42 * LAMPORTS_PER_SOL,
        );

        genesis_config.rent = Rent::default();
        genesis_config.epoch_schedule = EpochSchedule::new(SLOTS_PER_EPOCH);

        let (bank, bank_forks) =
            Bank::new_for_tests(&genesis_config).wrap_with_bank_forks_for_tests();
        let vote_address = Pubkey::new_unique();

        // Vote account just created
        let mut bank = apply_epoch_operations(
            bank,
            bank_forks.as_ref(),
            EpochOperations {
                epoch: 0,
                vote_operations: vec![(
                    vote_address,
                    VoteOperations {
                        create_with_balance: Some(LAMPORTS_PER_SOL),
                        new_commission: Some(1),
                        earned_credits: Some(1000),
                        delegate_stake_amount: Some(LAMPORTS_PER_SOL),
                        ..VoteOperations::default()
                    },
                )],
            },
        );

        for (epoch, (collector_address, maybe_account, expect_reward)) in [
            // system account with lamports, success
            (
                Pubkey::new_unique(),
                Some(AccountSharedData::new(
                    LAMPORTS_PER_SOL,
                    0,
                    &solana_sdk_ids::system_program::id(),
                )),
                true,
            ),
            // vote account, success
            (vote_address, None, true),
            // incinerator, success
            (incinerator::id(), None, true),
            // non-rent-exempt system account with 1 lamport, success with relaxed checks
            (
                Pubkey::new_unique(),
                Some(AccountSharedData::new(
                    1,
                    0,
                    &solana_sdk_ids::system_program::id(),
                )),
                true,
            ),
            // invalid owner, no commission
            (
                Pubkey::new_unique(),
                Some(AccountSharedData::new(
                    LAMPORTS_PER_SOL,
                    0,
                    &Pubkey::new_unique(),
                )),
                false,
            ),
            // reserved account, no commission
            (solana_sdk_ids::native_loader::id(), None, false),
            // non-rent-exempt system account, no commission
            (Pubkey::new_unique(), None, false),
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(account) = maybe_account {
                bank.store_account(&collector_address, &account);
            }
            bank = apply_epoch_operations(
                bank,
                bank_forks.as_ref(),
                EpochOperations {
                    epoch: epoch as u64 + 1,
                    vote_operations: vec![(
                        vote_address,
                        VoteOperations {
                            earned_credits: Some(1),
                            new_inflation_rewards_collector: Some(collector_address),
                            expect_reward,
                            ..VoteOperations::default()
                        },
                    )],
                },
            );
        }
    }
```

**File:** programs/vote/src/vote_state/mod.rs (L907-933)
```rust
/// Update the vote account's commission collector (SIMD-0232).
pub fn update_commission_collector<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedInstructionAccount,
    target_version: VoteStateTargetVersion,
    new_collector: NewCommissionCollector,
    kind: CommissionKind,
    signers: &HashSet<Pubkey, S>,
    rent: &Rent,
) -> Result<(), InstructionError> {
    let mut vote_state = get_vote_state_handler_checked(vote_account, target_version)?;

    // Require authorized withdrawer to sign.
    verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;

    let new_collector_key = new_collector.validate_and_resolve_key(vote_account, rent)?;

    match kind {
        CommissionKind::InflationRewards => {
            vote_state.set_inflation_rewards_collector(new_collector_key);
        }
        CommissionKind::BlockRevenue => {
            vote_state.set_block_revenue_collector(new_collector_key);
        }
    }

    vote_state.set_vote_account_state(vote_account)
}
```

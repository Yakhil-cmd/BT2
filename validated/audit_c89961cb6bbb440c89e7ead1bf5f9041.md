#No Vulnerability found for this question.

The code path traced confirms the accounting is correctly conserved and burns are properly excluded from capitalization:

1. At the entrypoint, `NewCommissionCollector::validate_and_resolve_key` already rejects non-system-owned, non-rent-exempt, and non-writable (reserved) accounts when the withdrawer calls `UpdateCommissionCollector` [1](#0-0) .

2. At epoch-boundary distribution, `Bank::collector_type_checked` re-validates the collector (owner, reserved-key list, rent-exemption or incinerator) at the time of actual distribution, independently of the set-time check [2](#0-1) .

3. In `load_and_reward_commission_accounts`, when `collector_type_checked` returns `Err` (reserved, wrong owner, or non-rent-exempt without the relaxed grandfather exception), the function returns `None` from the `filter_map` closure, which means the locally-mutated `commission_account` (with lamports already added) is **discarded and never stored** — the real on-chain account balance is untouched. The lamports are only tracked in `total_non_incinerator_burned_lamports`, and this is explicitly reported back as `burned_lamports` in `RewardCommissionLamportAmounts` [3](#0-2) .

4. In `distribute_reward_commissions`, `self.capitalization.fetch_add` is applied only to `distributed_lamports + distributed_to_incinerator_lamports`, explicitly excluding `burned_lamports` [4](#0-3) . There is also a hard `assert!` guaranteeing `point_value.rewards >= distributed_lamports + distributed_to_incinerator_lamports + burned_lamports + total_stake_rewards_lamports`, enforcing conservation [5](#0-4) .

5. The "relax_post_exec_min_balance_check" bypass for non-rent-exempt accounts is an intentional, tested grandfather exception (only applies when `pre_lamports != 0`, i.e., the account already existed with a balance before this deposit), not an attacker-controlled minting primitive [6](#0-5) ; this is exercised directly by `test_inflation_rewards_collector` [7](#0-6) .

6. Setting an unowned system-owned/rent-exempt account (or the vote account itself, or the incinerator) as a collector is explicit, documented, intended SIMD-0232 behavior — it does not require the withdrawer to own the destination account, and the worst outcome of choosing a "bad" future collector is that the vote account's own commission gets burned (self-inflicted), as demonstrated by `test_inflation_collector_becomes_vote_account_burns_rewards` and the code comment describing exactly this scenario [8](#0-7) . There is no path by which burned lamports get double-counted into capitalization or land in an account not intended to receive them, and no path for an unprivileged attacker to affect a victim's commission accounting since the collector is set only by the vote account's own authorized withdrawer.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L866-904)
```rust
impl NewCommissionCollector<'_, '_> {
    /// Validates the collector per SIMD-0232 and returns its pubkey.
    ///
    /// The designated commission collector must either be equal to the vote
    /// account's address OR satisfy ALL of the following constraints:
    ///
    /// 1. Must be a system program owned account.
    /// 2. Must be rent-exempt.
    /// 3. Must not be a reserved account (checked via writable flag).
    pub fn validate_and_resolve_key(
        &self,
        vote_account: &BorrowedInstructionAccount,
        rent: &Rent,
    ) -> Result<Pubkey, InstructionError> {
        match self {
            NewCommissionCollector::VoteAccount => Ok(*vote_account.get_key()),
            NewCommissionCollector::NewAccount(collector_account) => {
                // 1. Must be a system program owned account.
                if collector_account.get_owner() != &system_program::id() {
                    return Err(InstructionError::InvalidAccountOwner);
                }

                // 2. Must be rent-exempt.
                if !rent.is_exempt(
                    collector_account.get_lamports(),
                    collector_account.get_data().len(),
                ) {
                    return Err(InstructionError::InsufficientFunds);
                }

                // 3. Must not be a reserved account (checked via writable flag).
                if !collector_account.is_writable() {
                    return Err(InstructionError::InvalidArgument);
                }

                Ok(*collector_account.get_key())
            }
        }
    }
```

**File:** runtime/src/bank/fee_distribution.rs (L241-270)
```rust
    pub(super) fn collector_type_checked(
        collector_id: &Pubkey,
        pre_lamports: u64,
        account: &AccountSharedData,
        reserved_account_keys: &ReservedAccountKeys,
        rent: &Rent,
        relax_post_execution_balance_checks: bool,
    ) -> Result<ExternalCollectorType, DepositFeeError> {
        if !system_program::check_id(account.owner()) {
            return Err(DepositFeeError::InvalidAccountOwner);
        }

        if reserved_account_keys.is_reserved(collector_id) {
            return Err(DepositFeeError::ReservedCollector);
        }

        // Don't perform rent check on the incinerator, so that the deposit
        // always works. The incinerator is run at the end of a block
        if *collector_id == incinerator::id() {
            Ok(ExternalCollectorType::Incinerator)
        } else {
            if !rent.is_exempt(account.lamports(), account.data().len())
                && (!relax_post_execution_balance_checks || pre_lamports == 0)
            {
                Err(DepositFeeError::InvalidRentPayingAccount)
            } else {
                Ok(ExternalCollectorType::SystemAccount)
            }
        }
    }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L77-91)
```rust
///
/// * a vote account A sets the inflation collector to valid system account B
/// * at some point in the future, that system account B gets allocated and
///   initialized as a vote account B
/// * vote account B sets itself as the inflation reward collector
///
/// In that situation, the rewards for vote account A will get burned, but the
/// rewards for vote account B will not. According to the rules of SIMD-0232,
/// a collector account must either be the vote account itself or a system
/// account that fulfills certain criteria. In the case of vote account A, we
/// are already sure that the collector account is invalid.
///
/// NOTE: if vote account B sets a system account as its inflation collector,
/// then the commission lamports for vote account A will NOT get burned here,
/// but will get burned during `load_and_reward_commission_accounts`
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L397-408)
```rust
        // verify that we didn't pay any more than we expected to
        assert!(
            point_value.rewards
                >= distributed_lamports
                    + distributed_to_incinerator_lamports
                    + burned_lamports
                    + total_stake_rewards_lamports,
            "point_value={point_value:?}, distributed_lamports={distributed_lamports}, \
             distributed_to_incinerator_lamports={distributed_to_incinerator_lamports} \
             burned_lamports={burned_lamports}, \
             total_stake_rewards_lamports={total_stake_rewards_lamports}"
        );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L416-421)
```rust
        let num_stake_accounts = self.stakes_cache.stakes().stake_delegations().len();
        let num_vote_accounts = *num_filtered_vote_accounts;
        self.capitalization.fetch_add(
            distributed_lamports + distributed_to_incinerator_lamports,
            Relaxed,
        );
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L1150-1217)
```rust
                        if *burned_lamports != 0 {
                            total_non_incinerator_burned_lamports
                                .fetch_add(*burned_lamports, Relaxed);
                        }
                        let pre_lamports = commission_account.lamports();
                        if let Err(err) =
                            commission_account.checked_add_lamports(*commission_lamports)
                        {
                            debug!("reward redemption failed for {commission_pubkey}: {err:?}");
                            total_non_incinerator_burned_lamports
                                .fetch_add(*commission_lamports, Relaxed);
                            return None;
                        }
                        if !is_vote_account {
                            match Self::collector_type_checked(
                                commission_pubkey,
                                pre_lamports,
                                &commission_account,
                                reserved_account_keys,
                                rent,
                                relax_post_exec_min_balance_check,
                            ) {
                                Ok(ExternalCollectorType::SystemAccount) => {}
                                Ok(ExternalCollectorType::Incinerator) => {
                                    total_incinerator_lamports
                                        .fetch_add(*commission_lamports, Relaxed);
                                }
                                Err(err) => {
                                    debug!(
                                        "reward redemption failed for {commission_pubkey} due to \
                                         commission account error: {err:?}"
                                    );
                                    total_non_incinerator_burned_lamports
                                        .fetch_add(*commission_lamports, Relaxed);
                                    return None;
                                }
                            }
                        }
                        Some((
                            *commission_pubkey,
                            RewardInfo {
                                reward_type: RewardType::Voting,
                                lamports: *commission_lamports as i64,
                                post_balance: commission_account.lamports(),
                                commission_bps: *commission_bps,
                            },
                            commission_account,
                        ))
                    },
                )
                .collect()
        });

        let distributed_to_incinerator_lamports = total_incinerator_lamports.into_inner();
        let distributed_lamports = accounts_with_rewards
            .iter()
            .map(|(_, info, _)| info.lamports as u64)
            .sum::<u64>()
            .checked_sub(distributed_to_incinerator_lamports)
            .expect("incinerator lamports must be a subset of all distributed lamports");
        RewardCommissionAccounts {
            accounts_with_rewards,
            amounts: RewardCommissionLamportAmounts {
                distributed_lamports,
                distributed_to_incinerator_lamports,
                burned_lamports: total_non_incinerator_burned_lamports.into_inner(),
            },
        }
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L3787-3796)
```rust
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
```

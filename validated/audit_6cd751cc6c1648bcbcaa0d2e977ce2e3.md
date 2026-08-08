#No Vulnerability found for this question.

The withdraw() function at [1](#0-0)  already enforces `remaining_balance >= min_rent_exempt_balance + pending_delegator_rewards` via a checked_add guarded against overflow, and blocks full closure whenever `pending_delegator_rewards() > 0`. These checks are consensus-deterministic: `pending_delegator_rewards` is read from serialized on-chain vote state [2](#0-1) , and the SIMD-0123 feature gate is activated via the standard Agave feature-activation mechanism, which every validator observes identically at the same slot (feature activation itself is consensus state, not node-local config). There is no code path where one honest node evaluates `feature_set.commission_rate_in_basis_points`/`custom_commission_collector`/`block_revenue_sharing` differently from another honest node at the same slot, so the premised "feature-gate transition divergence" cannot occur from attacker-controlled instruction ordering alone.

Extensive existing unit tests already exercise exactly the boundary conditions described in the question (exact rent-exempt withdraw, exact `min_balance` boundary, full-close blocked while `pending_delegator_rewards > 0`, `ActiveVoteAccountClose` rejection when `epoch_credits` shows recent voting activity) and assert consistent, deterministic outcomes: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) .

Since the attacker cannot make the runtime evaluate a different feature set on different nodes, and the arithmetic/authority/rent checks are guarded (`checked_sub`, `checked_add` with `ArithmeticOverflow`, `verify_authorized_signer`), there is no reachable path to bank-hash divergence or theft/minting of lamports from this instruction sequence.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L1062-1129)
```rust
/// Withdraw funds from the vote account
pub fn withdraw<S: std::hash::BuildHasher>(
    instruction_context: &InstructionContext,
    vote_account_index: IndexOfAccount,
    target_version: VoteStateTargetVersion,
    lamports: u64,
    to_account_index: IndexOfAccount,
    signers: &HashSet<Pubkey, S>,
    rent_sysvar: &Rent,
    clock: &Clock,
) -> Result<(), InstructionError> {
    let mut vote_account =
        instruction_context.try_borrow_instruction_account(vote_account_index)?;
    let vote_state = get_vote_state_handler_checked(&vote_account, target_version)?;

    verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;

    let remaining_balance = vote_account
        .get_lamports()
        .checked_sub(lamports)
        .ok_or(InstructionError::InsufficientFunds)?;

    // Always zero until SIMD-0123 is activated.
    let pending_delegator_rewards = vote_state.pending_delegator_rewards();

    if remaining_balance == 0 {
        // SIMD-0123: vote account cannot be closed if
        // pending_delegator_rewards > 0.
        if pending_delegator_rewards > 0 {
            return Err(InstructionError::InsufficientFunds);
        }

        let reject_active_vote_account_close = vote_state
            .epoch_credits()
            .last()
            .map(|(last_epoch_with_credits, _, _)| {
                let current_epoch = clock.epoch;
                // if current_epoch - last_epoch_with_credits < 2 then the validator has received credits
                // either in the current epoch or the previous epoch. If it's >= 2 then it has been at least
                // one full epoch since the validator has received credits.
                current_epoch.saturating_sub(*last_epoch_with_credits) < 2
            })
            .unwrap_or(false);

        if reject_active_vote_account_close {
            return Err(VoteError::ActiveVoteAccountClose.into());
        } else {
            // Deinitialize upon zero-balance
            VoteStateHandler::deinitialize_vote_account_state(&mut vote_account, target_version)?;
        }
    } else {
        // SIMD-0123: withdrawable balance when pending_delegator_rewards > 0
        // is lamports - pending_delegator_rewards - rent_exempt_minimum.
        let min_rent_exempt_balance = rent_sysvar.minimum_balance(vote_account.get_data().len());
        let min_balance = min_rent_exempt_balance
            .checked_add(pending_delegator_rewards)
            .ok_or(InstructionError::ArithmeticOverflow)?;
        if remaining_balance < min_balance {
            return Err(InstructionError::InsufficientFunds);
        }
    }

    vote_account.checked_sub_lamports(lamports)?;
    drop(vote_account);
    let mut to_account = instruction_context.try_borrow_instruction_account(to_account_index)?;
    to_account.checked_add_lamports(lamports)?;
    Ok(())
}
```

**File:** programs/vote/src/vote_state/mod.rs (L5729-5796)
```rust
    fn test_withdraw(target_version: VoteStateTargetVersion) {
        // Verify withdraw boundary conditions around the rent-exempt
        // minimum: partial withdraw, full deinit, and over-withdraw.
        let vote_pubkey = solana_pubkey::new_rand();
        let vote_state = vote_state_new_for_test(&vote_pubkey, target_version);
        let withdrawer = *vote_state.authorized_withdrawer();
        let signers: HashSet<Pubkey> = [withdrawer].into_iter().collect();
        let rent = Rent::default();
        let serialized = vote_state.clone().serialize();
        let serialized_len = serialized.len();
        let min_balance = rent.minimum_balance(serialized_len);
        let clock = Clock {
            epoch: 100,
            ..Clock::default()
        };

        // Account at exact rent-exempt minimum: withdraw 1 fails.
        {
            let mut acct = AccountSharedData::new(min_balance, serialized_len, &id());
            acct.set_data_from_slice(&serialized);
            let transaction_context = setup_withdraw_context(vote_pubkey, acct);
            let ix = transaction_context.get_next_instruction_context().unwrap();
            assert_eq!(
                withdraw(&ix, 0, target_version, 1, 1, &signers, &rent, &clock),
                Err(InstructionError::InsufficientFunds)
            );
        }

        // Account at exact rent-exempt minimum: withdraw all succeeds (deinit).
        {
            let mut acct = AccountSharedData::new(min_balance, serialized_len, &id());
            acct.set_data_from_slice(&serialized);
            let transaction_context = setup_withdraw_context(vote_pubkey, acct);
            let ix = transaction_context.get_next_instruction_context().unwrap();
            withdraw(
                &ix,
                0,
                target_version,
                min_balance,
                1,
                &signers,
                &rent,
                &clock,
            )
            .unwrap();
        }

        // Account at rent_exempt + 100: withdraw 100 succeeds.
        {
            let mut acct = AccountSharedData::new(min_balance + 100, serialized_len, &id());
            acct.set_data_from_slice(&serialized);
            let transaction_context = setup_withdraw_context(vote_pubkey, acct);
            let ix = transaction_context.get_next_instruction_context().unwrap();
            withdraw(&ix, 0, target_version, 100, 1, &signers, &rent, &clock).unwrap();
        }

        // Account at rent_exempt + 100: withdraw 101 fails.
        {
            let mut acct = AccountSharedData::new(min_balance + 100, serialized_len, &id());
            acct.set_data_from_slice(&serialized);
            let transaction_context = setup_withdraw_context(vote_pubkey, acct);
            let ix = transaction_context.get_next_instruction_context().unwrap();
            assert_eq!(
                withdraw(&ix, 0, target_version, 101, 1, &signers, &rent, &clock),
                Err(InstructionError::InsufficientFunds)
            );
        }
    }
```

**File:** programs/vote/src/vote_state/mod.rs (L5817-5920)
```rust
    #[test]
    fn test_withdraw_with_pending_delegator_rewards() {
        // Verify withdraw protects pending_delegator_rewards: partial
        // withdrawals respect the pending reserve, and full close is
        // blocked when pending > 0.
        let vote_pubkey = solana_pubkey::new_rand();
        let rent = Rent::default();
        let clock = Clock {
            epoch: 100,
            ..Clock::default()
        };

        // pending = 1000, extra = 1000. withdrawable = 0.
        {
            let (handler, account) = make_v4_account_with_pending(&vote_pubkey, 1000, 1000);
            let withdrawer = *handler.authorized_withdrawer();
            let signers: HashSet<Pubkey> = [withdrawer].into_iter().collect();
            let tx = setup_withdraw_context(vote_pubkey, account);
            let ix = tx.get_next_instruction_context().unwrap();

            // Withdraw 1 fails (withdrawable = lamports - rent - pending = 0).
            assert_eq!(
                withdraw(
                    &ix,
                    0,
                    VoteStateTargetVersion::V4,
                    1,
                    1,
                    &signers,
                    &rent,
                    &clock
                ),
                Err(InstructionError::InsufficientFunds)
            );
        }

        // pending = 1000, extra = 1001. withdrawable = 1.
        {
            let (handler, account) = make_v4_account_with_pending(&vote_pubkey, 1000, 1001);
            let withdrawer = *handler.authorized_withdrawer();
            let signers: HashSet<Pubkey> = [withdrawer].into_iter().collect();
            let tx = setup_withdraw_context(vote_pubkey, account);
            let ix = tx.get_next_instruction_context().unwrap();

            // Withdraw 1 succeeds.
            withdraw(
                &ix,
                0,
                VoteStateTargetVersion::V4,
                1,
                1,
                &signers,
                &rent,
                &clock,
            )
            .unwrap();
        }

        // pending = 1000, extra = 1001. Withdraw 2 fails.
        {
            let (handler, account) = make_v4_account_with_pending(&vote_pubkey, 1000, 1001);
            let withdrawer = *handler.authorized_withdrawer();
            let signers: HashSet<Pubkey> = [withdrawer].into_iter().collect();
            let tx = setup_withdraw_context(vote_pubkey, account);
            let ix = tx.get_next_instruction_context().unwrap();

            assert_eq!(
                withdraw(
                    &ix,
                    0,
                    VoteStateTargetVersion::V4,
                    2,
                    1,
                    &signers,
                    &rent,
                    &clock
                ),
                Err(InstructionError::InsufficientFunds)
            );
        }

        // Full close blocked when pending > 0.
        {
            let (handler, account) = make_v4_account_with_pending(&vote_pubkey, 1, 1_000_000);
            let withdrawer = *handler.authorized_withdrawer();
            let signers: HashSet<Pubkey> = [withdrawer].into_iter().collect();
            let lamports = rent.minimum_balance(VoteStateV4::size_of()) + 1_000_000;
            let tx = setup_withdraw_context(vote_pubkey, account);
            let ix = tx.get_next_instruction_context().unwrap();

            assert_eq!(
                withdraw(
                    &ix,
                    0,
                    VoteStateTargetVersion::V4,
                    lamports,
                    1,
                    &signers,
                    &rent,
                    &clock
                ),
                Err(InstructionError::InsufficientFunds)
            );
        }
```

**File:** programs/vote/src/vote_state/handler.rs (L190-194)
```rust
    pub(crate) fn pending_delegator_rewards(&self) -> u64 {
        match &self.target_state {
            TargetVoteState::V4(v4) => v4.pending_delegator_rewards,
        }
    }
```

**File:** programs/vote/src/vote_processor.rs (L3055-3138)
```rust
    #[test]
    fn test_vote_state_withdraw() {
        let authorized_withdrawer_pubkey = solana_pubkey::new_rand();
        let (vote_pubkey_1, vote_account_with_epoch_credits_1) =
            create_test_account_with_epoch_credits(&[2, 1]);
        let (vote_pubkey_2, vote_account_with_epoch_credits_2) =
            create_test_account_with_epoch_credits(&[2, 1, 3]);
        let clock = Clock {
            epoch: 3,
            ..Clock::default()
        };
        let clock_account = account::create_account_shared_data_for_test(&clock);
        let rent_sysvar = Rent::default();
        let minimum_balance = rent_sysvar
            .minimum_balance(vote_account_with_epoch_credits_1.data().len())
            .max(1);
        let lamports = vote_account_with_epoch_credits_1.lamports();
        let transaction_accounts = vec![
            (vote_pubkey_1, vote_account_with_epoch_credits_1),
            (vote_pubkey_2, vote_account_with_epoch_credits_2),
            (sysvar::clock::id(), clock_account),
            (
                sysvar::rent::id(),
                account::create_account_shared_data_for_test(&rent_sysvar),
            ),
            (authorized_withdrawer_pubkey, AccountSharedData::default()),
        ];
        let mut instruction_accounts = vec![
            AccountMeta {
                pubkey: vote_pubkey_1,
                is_signer: true,
                is_writable: true,
            },
            AccountMeta {
                pubkey: authorized_withdrawer_pubkey,
                is_signer: false,
                is_writable: true,
            },
        ];

        let features = VoteProgramFeatures {
            ..Default::default()
        };

        // non rent exempt withdraw, with 0 credit epoch
        instruction_accounts[0].pubkey = vote_pubkey_1;
        process_instruction(
            features,
            &serialize(&VoteInstruction::Withdraw(lamports - minimum_balance + 1)).unwrap(),
            transaction_accounts.clone(),
            instruction_accounts.clone(),
            Err(InstructionError::InsufficientFunds),
        );

        // non rent exempt withdraw, without 0 credit epoch
        instruction_accounts[0].pubkey = vote_pubkey_2;
        process_instruction(
            features,
            &serialize(&VoteInstruction::Withdraw(lamports - minimum_balance + 1)).unwrap(),
            transaction_accounts.clone(),
            instruction_accounts.clone(),
            Err(InstructionError::InsufficientFunds),
        );

        // full withdraw, with 0 credit epoch
        instruction_accounts[0].pubkey = vote_pubkey_1;
        process_instruction(
            features,
            &serialize(&VoteInstruction::Withdraw(lamports)).unwrap(),
            transaction_accounts.clone(),
            instruction_accounts.clone(),
            Ok(()),
        );

        // full withdraw, without 0 credit epoch
        instruction_accounts[0].pubkey = vote_pubkey_2;
        process_instruction(
            features,
            &serialize(&VoteInstruction::Withdraw(lamports)).unwrap(),
            transaction_accounts,
            instruction_accounts,
            Err(VoteError::ActiveVoteAccountClose.into()),
        );
    }
```

**File:** programs/vote/src/vote_processor.rs (L5219-5302)
```rust
    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_withdraw_pending_delegator_rewards() {
        let rent_sysvar = Rent::default();
        let rent_minimum_balance = rent_sysvar.minimum_balance(VoteStateV4::size_of());

        let pending_rewards = 500_000;
        let extra_for_withdraw = 100_000;
        let vote_account_lamports = rent_minimum_balance + pending_rewards + extra_for_withdraw;

        let (vote_pubkey, _authorized_voter, authorized_withdrawer, mut vote_account) =
            create_test_account_with_authorized();

        // Set some pending delegator rewards.
        {
            let mut vote_state =
                VoteStateV4::deserialize(vote_account.data(), &vote_pubkey).unwrap();
            vote_state.pending_delegator_rewards = pending_rewards;
            vote_account.set_data_from_slice(&VoteStateHandler::new_v4(vote_state).serialize());
            vote_account.set_lamports(vote_account_lamports);
        };

        let features = VoteProgramFeatures::all_enabled();

        let instruction_accounts = vec![
            AccountMeta {
                pubkey: vote_pubkey,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: authorized_withdrawer,
                is_signer: true,
                is_writable: true,
            },
        ];

        let rent_account = account::create_account_shared_data_for_test(&rent_sysvar);
        let transaction_accounts = vec![
            (vote_pubkey, vote_account.clone()),
            (authorized_withdrawer, AccountSharedData::default()),
            (sysvar::clock::id(), create_default_clock_account()),
            (sysvar::rent::id(), rent_account.clone()),
        ];

        // Should fail, can't close vote account when
        // pending_delegator_rewards > 0.
        process_instruction(
            features,
            &serialize(&VoteInstruction::Withdraw(vote_account_lamports)).unwrap(),
            transaction_accounts.clone(),
            instruction_accounts.clone(),
            Err(InstructionError::InsufficientFunds),
        );

        // Should fail, can't withdraw more than
        // (lamports - pending_delegator_rewards - rent_exempt).
        process_instruction(
            features,
            &serialize(&VoteInstruction::Withdraw(vote_account_lamports + 1)).unwrap(),
            transaction_accounts.clone(),
            instruction_accounts.clone(),
            Err(InstructionError::InsufficientFunds),
        );

        // Should pass, can withdraw up to the max withdrawable amount.
        for i in 1..10 {
            let withdraw_amount = 1 + i * extra_for_withdraw / 10;

            let accounts = process_instruction(
                features,
                &serialize(&VoteInstruction::Withdraw(withdraw_amount)).unwrap(),
                transaction_accounts.clone(),
                instruction_accounts.clone(),
                Ok(()),
            );

            assert_eq!(
                accounts[0].lamports(),
                vote_account_lamports - withdraw_amount
            );
            assert!(accounts[0].lamports() >= rent_minimum_balance + pending_rewards);
            assert_eq!(accounts[1].lamports(), withdraw_amount);
        }
```

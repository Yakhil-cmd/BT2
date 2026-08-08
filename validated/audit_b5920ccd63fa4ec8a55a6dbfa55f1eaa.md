## Title
Vote program's `DepositDelegatorRewards` CPI to System is denied by the runtime's overly-strict reentrancy guard, causing loss of delegator reward deposits - (File: `programs/vote/src/vote_state/mod.rs`)

### Summary
`VoteInstruction::DepositDelegatorRewards` (SIMD-0123) is an unprivileged, permissionless vote-account instruction handled in `deposit_delegator_rewards()` [1](#0-0) . It performs a cross-program invocation into the System program to transfer lamports from a signer-supplied "source" account into the vote account, then updates `pending_delegator_rewards` after the CPI returns [2](#0-1) . This mirrors the reported bug class: a legitimate, benign call path is blocked because the runtime's single global reentrancy guard (`InvokeContext::push`) treats any repeated appearance of the same program in the instruction stack as reentrancy, unless it is the direct/last caller.

### Finding Description
`InvokeContext::push()` enforces SIMD-0184-style reentrancy protection: it errors with `InstructionError::ReentrancyNotAllowed` if the target program already exists anywhere in the current instruction stack, *unless* it is the immediately-preceding ("last") frame that is calling itself directly [3](#0-2) :

```
if contains && !is_last {
    // Reentrancy not allowed unless caller is calling itself
    return Err(InstructionError::ReentrancyNotAllowed);
}
```

This is a coarse, whole-stack check on `program_id` identity — it does not distinguish "malicious reentrancy" from "the same builtin program being legitimately invoked twice in different branches of an unrelated call tree" (exactly the false-positive pattern described in the external report, where two independent, unrelated `nonReentrant` guards on the same contract collide).

`deposit_delegator_rewards()` is reachable both as a top-level instruction and via CPI from any arbitrary calling program (it is a normal vote-program instruction, gated only by feature flags, not by caller identity) [4](#0-3) . Inside it, the vote program performs `invoke_context.native_invoke_signed(system_instruction::transfer(...), &[])` to move lamports from the source account to the vote account [5](#0-4) , which itself calls `InvokeContext::push()` through `process_instruction` internally.

If any caller earlier in the same transaction's instruction stack has already invoked the System program (a near-universal pattern — e.g., a caller program that creates/funds the source account via System before CPIing into the vote program's `DepositDelegatorRewards`, or a delegation-pool/staking-pool program that does `system_program::transfer` to top up a temporary account and then calls the vote program in the same instruction tree), the stack will already contain `system_program::id()` at some non-adjacent level. When the vote program's internal `native_invoke_signed` then attempts to push System program again, `contains` is true but `is_last` is false (the last frame is the vote program, not System), so the push fails with `ReentrancyNotAllowed`, and `deposit_delegator_rewards()` — and therefore the entire enclosing transaction — reverts.

This is architecturally identical to the reported issue: two independent, legitimate CPI edges into the "same" callee (here, the System program, analogous to the report's lender contract) collide inside a single global reentrancy tracking mechanism, causing an otherwise-valid state-changing operation (reward deposit / stake pool accounting) to be unconditionally denied.

### Impact Explanation
`DepositDelegatorRewards` is the mechanism by which delegator/commission rewards are credited into a vote account's `pending_delegator_rewards` per SIMD-0123 [6](#0-5) . If the CPI is blocked by the reentrancy guard whenever the calling program (e.g., a staking-pool or block-revenue distribution program) has already touched the System program earlier in its own call tree, reward deposits from that class of caller will permanently and deterministically fail on every attempt, denying delegators/validators their rewards through that code path. This matches the report's "Medium" impact class: legitimate accounting operations become uncallable, but no direct fund theft occurs — funds simply cannot be credited via this path, and downstream reward/commission accounting may become permanently stuck for affected callers.

### Likelihood Explanation
Likelihood depends entirely on whether any calling program that CPIs into `DepositDelegatorRewards` also invokes the System program elsewhere, non-adjacently, in the same instruction stack — a very common pattern for pool/aggregator programs that fund accounts via System transfers before delegating further calls. Given `DepositDelegatorRewards` is explicitly designed as a CPI-target instruction (its two accounts are `voteAccount` and `source`, with no restriction on the calling program) [7](#0-6) , this is a realistic, not merely theoretical, integration pattern for any staking-pool-style program built on top of vote accounts.

### Recommendation
Relax or scope the reentrancy check in `InvokeContext::push()` so that builtin, side-effect-limited programs such as System (or more generally, non-adjacent legitimate re-entries of a builtin already present in the stack) are not blanket-rejected, or restrict the check to the specific call edge relevant to the actual privilege/borrow being protected, similar to how the original report's fix removed the redundant/duplicate guard rather than the sole legitimate one.

### Proof of Concept
1. Program `A` (any external staking-pool style program) is invoked at the top level.
2. `A` issues `system_instruction::transfer` via CPI to fund/prepare an account — System program is now present in the instruction stack at nesting level 1.
3. `A` then CPIs into the Vote program with `VoteInstruction::DepositDelegatorRewards { deposit }`, with the required feature flags enabled — Vote program is pushed at nesting level 2.
4. Inside `deposit_delegator_rewards()`, the vote program calls `invoke_context.native_invoke_signed(system_instruction::transfer(...), &[])` [5](#0-4) , attempting to push System program at nesting level 3.
5. `InvokeContext::push()` finds System program already present at level 1 (`contains == true`) and the current top-of-stack program (level 2, Vote) is not System (`is_last == false`) [3](#0-2) , so it returns `InstructionError::ReentrancyNotAllowed`, aborting the whole transaction and preventing the reward deposit from ever completing for this integration pattern.

**Uncertainty**: I was not able to execute this scenario against a live/test bank in this session to confirm the exact error path end-to-end (e.g., whether `check_authorized_program` or some other earlier check intercepts first); this analysis is based on static code reading of `InvokeContext::push`, `native_invoke_signed`, and `deposit_delegator_rewards`. Running the described 3-level CPI scenario in `programs/vote/src/vote_processor.rs`'s test harness (which already registers the System program for CPI, see `process_instruction_with_cu_check`) would be the way to confirm this concretely [8](#0-7) .

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L936-988)
```rust
pub fn deposit_delegator_rewards<S: std::hash::BuildHasher>(
    invoke_context: &mut InvokeContext,
    vote_account_index: IndexOfAccount,
    sender_account_index: IndexOfAccount,
    deposit: u64,
    signers: &HashSet<Pubkey, S>,
) -> Result<(), InstructionError> {
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;

    let vote_address = *instruction_context.get_key_of_instruction_account(vote_account_index)?;
    let source_address =
        *instruction_context.get_key_of_instruction_account(sender_account_index)?;

    // Source account must sign the transfer.
    verify_authorized_signer(&source_address, signers)?;

    // SIMD-0123 states we must validate the vote account deserializes to a v4
    // *before* attempting CPI, then update the `pending_delegator_rewards`
    // field *last*.
    // We can deserialize it, and hold onto the deserialized payload in-memory.
    // This way, we can drop the account borrow but avoid re-deserializing
    // later, since we know only lamports will change.
    let mut vote_state = {
        let vote_account =
            instruction_context.try_borrow_instruction_account(vote_account_index)?;

        // Can't use `get_vote_state_handler_checked`, since it will convert
        // the underlying vote state to v4.
        // SIMD-0123 requires an *initialized v4*.
        let versioned = VoteStateVersions::deserialize(vote_account.get_data())?;
        if let VoteStateVersions::V4(vote_state_v4) = versioned {
            Ok(VoteStateHandler::new_v4(*vote_state_v4))
        } else {
            Err(InstructionError::InvalidAccountData)
        }
    }?;

    // CPI to System: Transfer from sender to vote account.
    invoke_context.native_invoke_signed(
        system_instruction::transfer(&source_address, &vote_address, deposit),
        &[],
    )?;

    // Update `pending_delegator_rewards`.
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut vote_account =
        instruction_context.try_borrow_instruction_account(vote_account_index)?;

    vote_state.add_pending_delegator_rewards(deposit)?;
    vote_state.set_vote_account_state(&mut vote_account)
}
```

**File:** program-runtime/src/invoke_context.rs (L280-299)
```rust
        if self.transaction_context.get_instruction_stack_height() != 0 {
            let contains =
                (0..self.transaction_context.get_instruction_stack_height()).any(|level| {
                    self.transaction_context
                        .get_instruction_context_at_nesting_level(level)
                        .and_then(|instruction_context| instruction_context.get_program_key())
                        .map(|program_key| program_key == program_id)
                        .unwrap_or(false)
                });
            let is_last = self
                .transaction_context
                .get_current_instruction_context()
                .and_then(|instruction_context| instruction_context.get_program_key())
                .map(|program_key| program_key == program_id)
                .unwrap_or(false);
            if contains && !is_last {
                // Reentrancy not allowed unless caller is calling itself
                return Err(InstructionError::ReentrancyNotAllowed);
            }
        }
```

**File:** programs/vote/src/vote_processor.rs (L409-426)
```rust
        VoteInstruction::DepositDelegatorRewards { deposit } => {
            // SIMD-0123: Deposit delegator rewards.
            // Requires:
            // * SIMD-0185: Vote State V4
            // * SIMD-0291: Commission in Basis Points
            // * SIMD-0232: Custom Commission Collector
            let feature_set = invoke_context.get_feature_set();
            if !feature_set.commission_rate_in_basis_points
                || !feature_set.custom_commission_collector
                || !feature_set.block_revenue_sharing
            {
                return Err(InstructionError::InvalidInstructionData);
            }

            instruction_context.check_number_of_instruction_accounts(2)?;
            drop(me);
            vote_state::deposit_delegator_rewards(invoke_context, 0, 1, deposit, &signers)
        }
```

**File:** programs/vote/src/vote_processor.rs (L547-596)
```rust
    fn process_instruction_with_cu_check(
        features: VoteProgramFeatures,
        instruction_data: &[u8],
        transaction_accounts: Vec<(Pubkey, AccountSharedData)>,
        instruction_accounts: Vec<AccountMeta>,
        expected_result: Result<(), InstructionError>,
        expected_cus: u64,
    ) -> Vec<AccountSharedData> {
        let VoteProgramFeatures {
            bls_pubkey_management_in_vote_account,
            commission_rate_in_basis_points,
            custom_commission_collector,
            block_revenue_sharing,
            vote_account_initialize_v2,
            alpenglow_migration_succeeded,
        } = features;
        let cu_consumed = RefCell::new(0u64);
        let accounts = mock_process_instruction_with_feature_set(
            &id(),
            instruction_data,
            transaction_accounts,
            instruction_accounts,
            expected_result,
            Entrypoint::register,
            |invoke_context| {
                invoke_context
                    .set_alpenglow_migration_succeeded_for_tests(alpenglow_migration_succeeded);
                // Register system program for CPI support.
                invoke_context.program_cache_for_tx_batch.replenish(
                    solana_sdk_ids::system_program::id(),
                    Arc::new(ProgramCacheEntry::new_builtin(
                        0,
                        solana_system_program::system_processor::Entrypoint::register,
                    )),
                );
                *cu_consumed.borrow_mut() = invoke_context.get_remaining();
            },
            |invoke_context| {
                *cu_consumed.borrow_mut() -= invoke_context.get_remaining();
            },
            &SVMFeatureSet {
                bls_pubkey_management_in_vote_account,
                commission_rate_in_basis_points,
                custom_commission_collector,
                block_revenue_sharing,
                vote_account_initialize_v2,
                ..SVMFeatureSet::all_enabled()
            },
        );
        assert_eq!(
```

**File:** transaction-status/src/parse_vote.rs (L322-332)
```rust
        VoteInstruction::DepositDelegatorRewards { deposit } => {
            check_num_vote_accounts(&instruction.accounts, 2)?;
            Ok(ParsedInstructionEnum {
                instruction_type: "depositDelegatorRewards".to_string(),
                info: json!({
                    "voteAccount": account_keys[instruction.accounts[0] as usize].to_string(),
                    "source": account_keys[instruction.accounts[1] as usize].to_string(),
                    "deposit": deposit,
                }),
            })
        }
```

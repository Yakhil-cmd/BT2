### Title
Unprivileged griefing of vote-account closure via unbounded `DepositDelegatorRewards` dust deposits - (File: `programs/vote/src/vote_state/mod.rs`, `programs/vote/src/vote_state/handler.rs`)

### Summary
The `DepositDelegatorRewards` vote instruction (SIMD-0123) lets *any* signer transfer an arbitrary amount of lamports into a vote account, incrementing the vote account's `pending_delegator_rewards` counter. `Withdraw` refuses to fully close a vote account (`remaining_balance == 0`) while `pending_delegator_rewards > 0`. Because the deposit instruction requires no authorization from the vote account's withdrawer — only the depositing "source" account must sign — an attacker can repeatedly deposit trivial amounts (e.g. 1 lamport) into a victim's vote account to keep `pending_delegator_rewards` permanently non-zero, indefinitely blocking the authorized withdrawer from fully closing the account, analogous to the referenced report's "excess receipts" DoS pattern.

### Finding Description
`deposit_delegator_rewards` in `programs/vote/src/vote_state/mod.rs` (lines 936-988) only requires the *sender* account to be a signer:
```
verify_authorized_signer(&source_address, signers)?;
...
vote_state.add_pending_delegator_rewards(deposit)?;
``` [1](#0-0) [2](#0-1) 

There is no requirement that the vote account's authorized withdrawer approve or that the deposit exceed a minimum size, so any account holding a trivial amount of lamports can call this instruction against an arbitrary target vote account, incrementing `pending_delegator_rewards` via `add_pending_delegator_rewards` in `programs/vote/src/vote_state/handler.rs`: [3](#0-2) 

`withdraw()` in `programs/vote/src/vote_state/mod.rs` then hard-blocks full closure of the vote account whenever `pending_delegator_rewards > 0`:
```
if remaining_balance == 0 {
    // SIMD-0123: vote account cannot be closed if
    // pending_delegator_rewards > 0.
    if pending_delegator_rewards > 0 {
        return Err(InstructionError::InsufficientFunds);
    }
    ...
``` [4](#0-3) 

Partial withdrawals are also constrained to always leave `rent_exempt_minimum + pending_delegator_rewards` behind: [5](#0-4) 

This mirrors the referenced report's structure exactly: an unprivileged party can create an unbounded (here, small but persistent) obligation attached to a resource that the legitimate owner must fully clear before performing a privileged terminal action (closing/fully withdrawing). Unlike a pool receipt system where the owner can eventually call `withdraw()` on each receipt to zero them out, `pending_delegator_rewards` is only reduced by the stake/reward distribution pipeline (`runtime/src/bank/partitioned_epoch_rewards/calculation.rs`), which decrements it in proportion to computed delegator rewards actually redeemed for that vote account's delegators — not simply by the deposited dust amount. If the targeted vote account has little or no stake, or the redemption path never drains exactly the dust amount deposited by the attacker, the withdrawer has no direct, per-account instruction to unilaterally zero out `pending_delegator_rewards` and force closure; they are dependent on the reward-distribution logic eventually reducing the counter to zero, which is not guaranteed to occur promptly or completely for adversarially-chosen dust amounts.

### Impact Explanation
This does not enable direct fund theft or consensus divergence, so it does not meet the "concrete unsigned fund movement, CPI privilege escalation, consensus divergence, stake/reward corruption, replay, or transaction-triggered cluster halt" bar required for a Critical/High analog. The impact is a griefing/availability issue: an attacker can indefinitely deny an authorized withdrawer the ability to fully close their own vote account and reclaim its rent-exempt balance, and can perpetually re-top a tiny nonzero `pending_delegator_rewards` balance at negligible cost each time the withdrawer manages to reduce it near zero. This is a service-availability degradation for a legitimate account owner, not a cluster-wide or fund-safety violation.

### Likelihood Explanation
Likelihood is high for triggering the griefing condition itself (any account with a small lamport balance can call `DepositDelegatorRewards` against any target vote account with no cooperation from the withdrawer), but the "unbounded gas/iteration" severity of the original report does not transfer 1:1, since `pending_delegator_rewards` is a single scalar field (O(1) to check), not a list of receipts requiring per-item withdrawal. The primary corroborated consequence is denial of full account closure, not unbounded computational/gas cost.

### Recommendation
- Require the vote account's authorized withdrawer to co-sign or explicitly opt in to `DepositDelegatorRewards`, or restrict the instruction to only be callable by the stake/reward-distribution pipeline rather than arbitrary user-supplied "source" accounts.
- Alternatively, provide an authorized-withdrawer-only instruction path to forgive/zero out residual dust `pending_delegator_rewards` (e.g., below a minimum threshold) so that account closure is not indefinitely blockable by trivial deposits from third parties.
- Enforce a minimum deposit size for `DepositDelegatorRewards`, mirroring the original report's recommended mitigation of a minimum deposit amount.

### Proof of Concept
1. Attacker identifies target vote account `V` with authorized withdrawer `W`.
2. Attacker funds a throwaway keypair `S` with a minimal lamport balance (e.g., rent-exempt minimum + 1).
3. Attacker submits a `DepositDelegatorRewards { deposit: 1 }` instruction with accounts `[V (writable), S (signer, writable), system_program]`, per the instruction handling in `programs/vote/src/vote_processor.rs` (lines 409-426): [6](#0-5) 
4. This succeeds and sets `V`'s `pending_delegator_rewards = 1` (per `deposit_delegator_rewards`), with no involvement or consent from `W`.
5. `W` later attempts to fully close `V` via `Withdraw(all_lamports)`; this is rejected with `InstructionError::InsufficientFunds` because `pending_delegator_rewards > 0`, as directly demonstrated in the existing test `test_withdraw_pending_delegator_rewards`: [7](#0-6) 
6. Attacker can repeat step 3 with a fresh 1-lamport deposit whenever `pending_delegator_rewards` approaches zero via reward distribution, perpetually denying `W` the ability to fully close and reclaim `V`'s balance.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L950-951)
```rust
    // Source account must sign the transfer.
    verify_authorized_signer(&source_address, signers)?;
```

**File:** programs/vote/src/vote_state/mod.rs (L986-987)
```rust
    vote_state.add_pending_delegator_rewards(deposit)?;
    vote_state.set_vote_account_state(&mut vote_account)
```

**File:** programs/vote/src/vote_state/mod.rs (L1084-1092)
```rust
    // Always zero until SIMD-0123 is activated.
    let pending_delegator_rewards = vote_state.pending_delegator_rewards();

    if remaining_balance == 0 {
        // SIMD-0123: vote account cannot be closed if
        // pending_delegator_rewards > 0.
        if pending_delegator_rewards > 0 {
            return Err(InstructionError::InsufficientFunds);
        }
```

**File:** programs/vote/src/vote_state/mod.rs (L1112-1121)
```rust
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
```

**File:** programs/vote/src/vote_state/handler.rs (L196-209)
```rust
    pub(crate) fn add_pending_delegator_rewards(
        &mut self,
        amount: u64,
    ) -> Result<(), InstructionError> {
        match &mut self.target_state {
            TargetVoteState::V4(v4) => {
                v4.pending_delegator_rewards = v4
                    .pending_delegator_rewards
                    .checked_add(amount)
                    .ok_or(InstructionError::ArithmeticOverflow)?;
                Ok(())
            }
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

**File:** programs/vote/src/vote_processor.rs (L5264-5272)
```rust
        // Should fail, can't close vote account when
        // pending_delegator_rewards > 0.
        process_instruction(
            features,
            &serialize(&VoteInstruction::Withdraw(vote_account_lamports)).unwrap(),
            transaction_accounts.clone(),
            instruction_accounts.clone(),
            Err(InstructionError::InsufficientFunds),
        );
```

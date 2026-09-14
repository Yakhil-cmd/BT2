### Title
Vote account `InitializeAccount` can be front-run to hijack `authorized_withdrawer`/`authorized_voter` and steal funded lamports - (`programs/vote/src/vote_state/mod.rs`, `programs/vote/src/vote_processor.rs`)

### Summary
The vote program's `InitializeAccount`/`InitializeAccountV2` handler does not require a signature from the vote account itself, only from `vote_init.node_pubkey`. Any unprivileged transaction sender can watch for a `SystemInstruction::CreateAccount` that funds and assigns a new, not-yet-initialized address to the vote program, and race a separate `InitializeAccount` transaction naming themselves as `authorized_withdrawer`/`authorized_voter` before the legitimate owner's initialize transaction lands. This mirrors the reported "initialize can be front run" bug class from the Solidity report, where a permissionless initializer sets owner/critical roles with no restriction on who calls it or when.

### Finding Description
`VoteInstruction::InitializeAccount(vote_init)` is dispatched in `declare_process_instruction!` in `programs/vote/src/vote_processor.rs:130-140`, where the vote account instruction meta has `is_signer: false` (confirmed by tests, e.g. `programs/vote/src/vote_processor.rs:945-966` and `programs/vote/benches/vote_instructions.rs:309-330`). The only signer check performed is on `vote_init.node_pubkey`: [1](#0-0) 

```
pub fn initialize_account<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedInstructionAccount,
    ...
) -> Result<(), InstructionError> {
    VoteStateHandler::check_vote_account_length(vote_account, target_version)?;
    let versioned = vote_account.get_state::<VoteStateVersions>()?;
    if !versioned.is_uninitialized() {
        return Err(InstructionError::AccountAlreadyInitialized);
    }
    // node must agree to accept this vote account
    verify_authorized_signer(&vote_init.node_pubkey, signers)?;
    VoteStateHandler::init_vote_account_state(vote_account, vote_init, clock, target_version)
}
```

No check requires that `vote_account`'s own key sign, and no check ties `authorized_voter`/`authorized_withdrawer` to any pre-existing authority (there is none yet, by design, since the account is uninitialized). Consequently, once a vote-program-owned, rent-exempt, uninitialized account exists at a given pubkey (created via `SystemInstruction::CreateAccount`), **anyone** who can produce a signer for an arbitrary `node_pubkey` (trivially, their own throwaway keypair) can call `InitializeAccount` on that address and set themselves as `authorized_withdrawer`.

Because `InitializeAccount` can only be executed once per uninitialized lifetime (`AccountAlreadyInitialized` guards re-init, per `programs/vote/src/vote_processor.rs:990-1001`), whichever transaction lands first wins permanently — this is the classic "initialize is front-runnable" pattern from the report, applied to a native Solana program rather than a Solidity contract.

Once the attacker controls `authorized_withdrawer`, they can drain the account's lamports via `Withdraw`, which only checks the withdrawer signer, not any relationship to the original creator/funder: [2](#0-1) 

```
pub fn withdraw<S: std::hash::BuildHasher>(
    ...
) -> Result<(), InstructionError> {
    let mut vote_account = instruction_context.try_borrow_instruction_account(vote_account_index)?;
    let vote_state = get_vote_state_handler_checked(&vote_account, target_version)?;
    verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;
    ...
    vote_account.checked_sub_lamports(lamports)?;
    ...
    to_account.checked_add_lamports(lamports)?;
    Ok(())
}
```

### Impact Explanation
This produces concrete unsigned fund movement: an attacker who never controlled the vote account's private key, and never had a legitimate stake/authorization relationship with it, can seize `authorized_withdrawer` rights over lamports funded into a freshly created vote account and subsequently drain them to an address of their choosing via `Withdraw`. It also permanently denies the legitimate operator control of the intended vote account address (their later `InitializeAccount` call fails with `AccountAlreadyInitialized`), forcing them to create a new account and re-fund it, and it lets the attacker set `authorized_voter`/`node_pubkey` for that address, potentially confusing off-chain tooling and delegators that expect the account to belong to the original creator.

### Likelihood Explanation
This requires the standard two-step "create then initialize" pattern to be executed as two separate transactions (or, if bundled atomically in a single transaction with the true owner's signatures on other instructions, the account itself is still not a required signer for `InitializeAccount`, so within a single legitimate transaction there is no race — the risk applies specifically when `CreateAccount` and `InitializeAccount` are sent as separate transactions, e.g., manual CLI flows or scripted tooling that funds an account first and initializes later). I was unable to fully confirm from the indexed code whether the current `solana-cli` `vote-account` creation path always bundles both instructions atomically in one transaction (my search for the exact CLI vote-account creation instruction list was inconclusive due to index limits), so the exploitability depends on real-world usage patterns outside of the always-atomic CLI helper. Where separate transactions are used (which is common for scripted/automated validator onboarding, multisig flows, or custom tooling), the race is straightforward for any mempool-observing attacker.

### Recommendation
Require that the vote account itself sign `InitializeAccount`/`InitializeAccountV2` (or otherwise cryptographically bind the resulting `authorized_withdrawer`/`authorized_voter` to a signer already known to the creator), so that only the entity holding the vote account's private key — established at `CreateAccount` time — can complete initialization. Alternatively, document and enforce (at the CLI/SDK level) that `CreateAccount` and `InitializeAccount` for vote accounts must always be submitted atomically within a single transaction, eliminating the front-runnable window between account creation and initialization.

### Proof of Concept
1. Legitimate operator submits `Transaction A`: `SystemInstruction::CreateAccount(payer, vote_pubkey, lamports=rent_exempt_min, space=VoteStateV4::size_of(), owner=vote_program::id())`, signed by `payer` and `vote_pubkey`. This transaction lands on-chain, creating an uninitialized, vote-program-owned, rent-exempt account.
2. Operator prepares `Transaction B`: `VoteInstruction::InitializeAccount(VoteInit{node_pubkey: operator_node, authorized_voter: operator, authorized_withdrawer: operator, commission})`, but has not yet had it confirmed.
3. Attacker observes `Transaction A` confirmed (or sees `Transaction B` in flight) and submits `Transaction C` first: `VoteInstruction::InitializeAccount(VoteInit{node_pubkey: attacker_key, authorized_voter: attacker_key, authorized_withdrawer: attacker_key, commission})` targeting the same `vote_pubkey`, signed only by `attacker_key` as `node_pubkey` (per the account-meta layout confirmed in `programs/vote/src/vote_processor.rs:130-140`, `vote_pubkey` itself is `is_signer: false`).
4. `Transaction C` succeeds because the account state is `State::Uninitialized`; `verify_authorized_signer(&vote_init.node_pubkey, signers)` passes since attacker signs as `node_pubkey`; `authorized_withdrawer` is set to `attacker_key`.
5. Operator's `Transaction B` (InitializeAccount) now fails with `InstructionError::AccountAlreadyInitialized` (per test at `programs/vote/src/vote_processor.rs:990-1001`).
6. Attacker submits `VoteInstruction::Withdraw(lamports)` signed by `attacker_key` (as `authorized_withdrawer`), draining the account's rent-exempt lamports to an address of their choosing, per `programs/vote/src/vote_state/mod.rs:1062-1128`.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L1062-1128)
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
```

**File:** programs/vote/src/vote_state/mod.rs (L1191-1209)
```rust
pub fn initialize_account<S: std::hash::BuildHasher>(
    vote_account: &mut BorrowedInstructionAccount,
    target_version: VoteStateTargetVersion,
    vote_init: &VoteInit,
    signers: &HashSet<Pubkey, S>,
    clock: &Clock,
) -> Result<(), InstructionError> {
    VoteStateHandler::check_vote_account_length(vote_account, target_version)?;
    let versioned = vote_account.get_state::<VoteStateVersions>()?;

    if !versioned.is_uninitialized() {
        return Err(InstructionError::AccountAlreadyInitialized);
    }

    // node must agree to accept this vote account
    verify_authorized_signer(&vote_init.node_pubkey, signers)?;

    VoteStateHandler::init_vote_account_state(vote_account, vote_init, clock, target_version)
}
```

### No vulnerability found for this question.

Setting the commission collector requires the vote account's `authorized_withdrawer` to sign, enforced explicitly by `verify_authorized_signer(vote_state.authorized_withdrawer(), signers)` in `update_commission_collector` [1](#0-0) , which is invoked from the `VoteInstruction::UpdateCommissionCollector` handler after checking `custom_commission_collector` feature gating [2](#0-1) . A stake account's delegator has no signer authority over the vote account it delegates to — delegating stake never grants control of `authorized_withdrawer`, `node_pubkey`, or any vote-state field. Consequently, an attacker who is merely a delegator to a vote account (i.e., controls a stake account pointed at that vote account) cannot invoke `UpdateCommissionCollector` successfully, since they cannot produce the required `authorized_withdrawer` signature.

The new collector value is additionally constrained via `NewCommissionCollector::validate_and_resolve_key`, requiring the target either be the vote account itself or a system-owned, rent-exempt, writable account [3](#0-2) , which further restricts the redirection target but is not the primary defense here — the primary defense is the authorized-withdrawer signer check.

Downstream, `redeem_delegation_rewards` reads `vote_state.inflation_rewards_collector()` to determine `commission_pubkey` only when `custom_commission_collector` is enabled [4](#0-3) , and this value can only have been set by whoever legitimately holds `authorized_withdrawer` authority over that specific vote account (the validator operator), not by an arbitrary stake delegator. This is confirmed by the test `test_update_commission_collector`, which exercises the withdrawer-signed path and by tests checking the missing-signature failure case (e.g., `test_vote_update_validator_identity`'s signer checks pattern applies analogously to `UpdateCommissionCollector`) [5](#0-4) .

Since the described attacker (an unprivileged stake delegator lacking authorized-withdrawer control) cannot pass the existing signer check, the described exploit path is not reachable.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L866-905)
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
}
```

**File:** programs/vote/src/vote_state/mod.rs (L916-921)
```rust
    let mut vote_state = get_vote_state_handler_checked(vote_account, target_version)?;

    // Require authorized withdrawer to sign.
    verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;

    let new_collector_key = new_collector.validate_and_resolve_key(vote_account, rent)?;
```

**File:** programs/vote/src/vote_state/mod.rs (L4570-4581)
```rust
    /// Test update_commission_collector (SIMD-0232).
    ///
    /// This test only uses V4 since SIMD-0232 depends on SIMD-0185 (VoteStateV4).
    #[test]
    fn test_update_commission_collector() {
        let target_version = VoteStateTargetVersion::V4;
        let vote_pubkey = solana_pubkey::new_rand();
        let vote_state = vote_state_new_for_test(&vote_pubkey, target_version);
        let withdrawer_pubkey = *vote_state.authorized_withdrawer();
        let node_pubkey = *vote_state.node_pubkey();

        let signers: HashSet<Pubkey> = vec![withdrawer_pubkey].into_iter().collect();
```

**File:** programs/vote/src/vote_processor.rs (L383-407)
```rust
        VoteInstruction::UpdateCommissionCollector(kind) => {
            // SIMD-0232: Custom Commission Collector Account
            // Requires SIMD-0185: Vote State V4
            let custom_collector_enabled =
                invoke_context.get_feature_set().custom_commission_collector;
            if !custom_collector_enabled {
                return Err(InstructionError::InvalidInstructionData);
            }

            instruction_context.check_number_of_instruction_accounts(3)?;
            let new_collector = read_new_collector_account(&instruction_context, &me, 1)?;

            let rent = invoke_context
                .environment_config
                .sysvar_cache()
                .get_rent()?;

            vote_state::update_commission_collector(
                &mut me,
                target_version,
                new_collector,
                kind,
                &signers,
                &rent,
            )
```

**File:** runtime/src/bank/partitioned_epoch_rewards/calculation.rs (L750-757)
```rust
                let (commission_pubkey, is_vote_account) = if custom_commission_collector {
                    let commission_pubkey = *vote_state
                        .inflation_rewards_collector()
                        .unwrap_or(&vote_pubkey);
                    (commission_pubkey, commission_pubkey == vote_pubkey)
                } else {
                    (vote_pubkey, true)
                };
```

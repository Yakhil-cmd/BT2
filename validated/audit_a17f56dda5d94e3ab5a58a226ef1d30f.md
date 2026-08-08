### Title
Vote program `authorize()` sets `authorized_withdrawer`/`authorized_voter` without rejecting `Pubkey::default()`, permanently freezing the vote account - (File: `programs/vote/src/vote_state/mod.rs`)

### Summary
The reported external issue is that `MainToken.set_mint_multisig()` allows setting a critical authority to the zero address with no validation, permanently losing control of that authority. The analogous unprivileged-user-reachable pattern in agave exists in the vote program's `authorize` instruction handler, which updates `authorized_withdrawer` and `authorized_voter` on a `VoteState` from a caller-supplied `Pubkey` with no check that the new authority isn't the "null" `Pubkey::default()`.

### Finding Description
`vote_state::authorize()` handles the `VoteInstruction::Authorize`/`AuthorizeChecked` instruction path. For the `Withdrawer` case, after verifying the current authorized withdrawer signed, it directly calls `vote_state.set_authorized_withdrawer(*authorized)` with the caller-supplied `authorized` pubkey — there is no check that `authorized != Pubkey::default()`: [1](#0-0) 

Similarly, the `Voter` branch calls `vote_state.set_new_authorized_voter(authorized, ...)` with the same unchecked, caller-controlled pubkey: [2](#0-1) 

`Pubkey::default()` (the all-zero pubkey) has no known private key, so once it is set as `authorized_withdrawer`, no future signer can ever satisfy `verify_authorized_signer(vote_state.authorized_withdrawer(), signers)` for that account. The `stake-authorize` CLI path shows the same unchecked pattern is expected by design — the CLI simply forwards a user-supplied pubkey to `stake_instruction::authorize()`/`stake_instruction::authorize_checked()` with no zero-address guard visible in the CLI-side authorization construction: [3](#0-2)  and the equivalent vote CLI path constructs the instruction from a raw `new_authorized_pubkey` argument without a default-pubkey check: [4](#0-3) . I was not able to locate the analogous stake-program instruction handler source (`programs/stake/src/*`) in the indexed content to confirm whether it has an equivalent unchecked write path for `Authorized.staker`/`Authorized.withdrawer`; this is a gap in my verification for the stake program specifically, though the CLI-level construction pattern is identical.

### Impact Explanation
If the current `authorized_withdrawer` (a normal, unprivileged validator-identity/vote-account key — not a privileged operator role) is set to `Pubkey::default()`, either by user error (e.g., a CLI/script bug passing an empty/zeroed pubkey) or a bug in a delegating tool, the vote account's ability to authorize a new withdrawer, withdraw lamports from the vote account, or close the account is permanently and irrecoverably lost, since no one holds the private key for the zero pubkey. This falls into the "permanently frozen accounts" impact category: funds and future authority-changes on the vote account become inaccessible forever with no on-chain recovery path.

### Likelihood Explanation
Likelihood is driven purely by operational/tooling error rather than adversarial exploitation, since a self-inflicted foot-gun requires the current authority to sign the transaction. However, given that vote-account setup and re-key operations are routine, high-value, and often scripted, an accidental zero/default pubkey substitution (e.g., an uninitialized variable serialized as `Pubkey::default()`) is a realistic failure mode identical in nature to the reported `set_mint_multisig()` bug.

### Recommendation
In `vote_state::authorize()` (and any equivalent stake-program authorize path), reject `authorized == Pubkey::default()` before calling `set_authorized_withdrawer` or `set_new_authorized_voter`, returning `InstructionError::InvalidInstructionData` (or similar) instead of silently accepting a permanently unrecoverable authority.

### Proof of Concept
1. Vote account `V` has `authorized_withdrawer = W`.
2. `W` signs a `VoteInstruction::Authorize(Pubkey::default(), VoteAuthorize::Withdrawer)` instruction (e.g., due to a scripting bug passing an uninitialized/default pubkey).
3. `vote_state::authorize()` executes `verify_authorized_signer(vote_state.authorized_withdrawer(), signers)` (passes, since `W` is the current authority) then unconditionally calls `vote_state.set_authorized_withdrawer(Pubkey::default())`, per [1](#0-0) .
4. From this point on, no transaction can ever provide a valid signer matching `Pubkey::default()`, so `Withdraw`, `AuthorizeWithSeed`, or any future `Authorize(Withdrawer)` instruction on `V` will fail with `MissingRequiredSignature` forever, permanently freezing the account's lamports and authority.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L701-726)
```rust
    match vote_authorize {
        VoteAuthorize::Voter => {
            if is_vote_authorize_with_bls_enabled && vote_state.has_bls_pubkey() {
                return Err(InstructionError::InvalidInstructionData);
            }
            let authorized_withdrawer_signer =
                verify_authorized_signer(vote_state.authorized_withdrawer(), signers).is_ok();

            vote_state.set_new_authorized_voter(
                authorized,
                clock.epoch,
                clock
                    .leader_schedule_epoch
                    .checked_add(1)
                    .ok_or(InstructionError::InvalidAccountData)?,
                None,
                |epoch_authorized_voter| {
                    // current authorized withdrawer or authorized voter must say "yay"
                    if authorized_withdrawer_signer {
                        Ok(())
                    } else {
                        verify_authorized_signer(&epoch_authorized_voter, signers)
                    }
                },
            )?;
        }
```

**File:** programs/vote/src/vote_state/mod.rs (L727-731)
```rust
        VoteAuthorize::Withdrawer => {
            // current authorized withdrawer must say "yay"
            verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;
            vote_state.set_authorized_withdrawer(*authorized);
        }
```

**File:** cli/src/stake.rs (L1619-1635)
```rust
        if new_authority_signer.is_some() {
            ixs.push(stake_instruction::authorize_checked(
                stake_account_pubkey, // stake account to update
                &authority.pubkey(),  // currently authorized
                new_authority_pubkey, // new stake signer
                *authorization_type,  // stake or withdraw
                custodian.map(|signer| signer.pubkey()).as_ref(),
            ));
        } else {
            ixs.push(stake_instruction::authorize(
                stake_account_pubkey, // stake account to update
                &authority.pubkey(),  // currently authorized
                new_authority_pubkey, // new stake signer
                *authorization_type,  // stake or withdraw
                custodian.map(|signer| signer.pubkey()).as_ref(),
            ));
        }
```

**File:** cli/src/vote.rs (L1295-1309)
```rust
    let vote_ix = if is_checked {
        vote_instruction::authorize_checked(
            vote_account_pubkey,      // vote account to update
            &authorized.pubkey(),     // current authorized
            new_authorized_pubkey,    // new vote signer/withdrawer
            effective_vote_authorize, // vote or withdraw
        )
    } else {
        vote_instruction::authorize(
            vote_account_pubkey,      // vote account to update
            &authorized.pubkey(),     // current authorized
            new_authorized_pubkey,    // new vote signer/withdrawer
            effective_vote_authorize, // vote or withdraw
        )
    };
```

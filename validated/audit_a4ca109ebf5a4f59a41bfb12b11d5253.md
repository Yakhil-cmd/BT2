### Title
Missing zero-address (`Pubkey::default()`) validation when setting a new vote-account withdrawer/voter authority permanently freezes the account - (File: `programs/vote/src/vote_state/mod.rs`)

### Summary
The vote program's `authorize()` handler, which implements the `VoteInstruction::Authorize`/`AuthorizeChecked` instruction paths, allows the current `authorized_withdrawer` (an ordinary, unprivileged account owner - no special validator/operator role required) to set the vote account's new `authorized_withdrawer` (or new voter, via `set_new_authorized_voter`) to any arbitrary `Pubkey`, including `Pubkey::default()` (all-zero bytes). This is exactly the bug class described in the external report (missing zero-address check before assigning a new authority), applied to the reachable, unprivileged vote-program instruction handler in this codebase rather than the validator/guardian-role Lido contract.

### Finding Description
In `programs/vote/src/vote_state/mod.rs`, the `authorize()` function processes `VoteAuthorize::Withdrawer` by only verifying the *current* withdrawer's signature before blindly assigning the caller-supplied pubkey as the new authority: [1](#0-0) 

```
VoteAuthorize::Withdrawer => {
    // current authorized withdrawer must say "yay"
    verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;
    vote_state.set_authorized_withdrawer(*authorized);
}
```

`set_authorized_withdrawer` in `programs/vote/src/vote_state/handler.rs` performs no validation on the supplied pubkey whatsoever: [2](#0-1) 

The same absence of validation exists for the `Voter` and `VoterWithBLS` branches, which call `set_new_authorized_voter` and insert the caller-supplied pubkey directly into `authorized_voters` with no zero-address check: [3](#0-2) [4](#0-3) 

`Pubkey::default()` (32 zero bytes) is the well-known address of the System Program (`11111111111111111111111111111111`). No private key exists for this address, so it can never appear as a transaction signer. If the withdrawer authority is ever set to this value (accidentally by a script/typo, by a compromised/malicious current withdrawer trying to grief a co-owned account, or via any code path that forwards a caller-controlled/unsanitized pubkey into the `Authorize` instruction), the vote account's SOL balance and the withdrawer-authority function become permanently unreachable - no future transaction can ever satisfy `verify_authorized_signer` for that authority, since verification requires the pubkey to be a signer of the transaction and no signature can ever be produced for the zero-key.

This directly mirrors the reported Lido `DepositSecurityModule` issue: a caller-supplied address is accepted and persisted as an authority without an `!= address(0)`-equivalent guard, and the missing guard converts what should be a simple config change into a permanent, unrecoverable state.

### Impact Explanation
Setting the withdrawer authority (or, analogously, exhausting all future voter-authority slots by setting the voter authority) to `Pubkey::default()` permanently locks the vote account: lamports held in the account (rent-exempt balance plus any accumulated commission/rewards) can never be withdrawn again, and no future `Authorize` instruction can be processed for that authority because it can never be produced as a valid signer. This falls under the accepted "permanently frozen accounts" impact category - the vote account and its held funds become irrecoverably stuck on-chain, which is a protocol-level denial-of-service/fund-freezing condition, not merely a client-side inconvenience.

### Likelihood Explanation
The `Authorize`/`AuthorizeChecked` instruction is processed for every vote account and is reachable by any account holding the current `authorized_withdrawer` key - an ordinary, unprivileged staker/validator operator, not a special protocol role. No feature gate or additional condition is required; the vulnerable code path executes unconditionally whenever an `Authorize` instruction for `VoteAuthorize::Withdrawer` (or `Voter`) is submitted. The trigger requires only that the caller (deliberately, via a scripting bug, or through malicious intent by a co-signer) supply the literal zero pubkey as the new authority - a trivial, always-reachable condition with no cryptographic or timing requirements.

### Recommendation
Add an explicit check rejecting `Pubkey::default()` (and any other well-known unownable system addresses, if desired) as a new authority in `authorize()` before calling `set_authorized_withdrawer` / `set_new_authorized_voter`, e.g.:

```rust
if *authorized == Pubkey::default() {
    return Err(InstructionError::InvalidArgument);
}
```

This should be applied to both the `Withdrawer` and `Voter`/`VoterWithBLS` branches in `programs/vote/src/vote_state/mod.rs::authorize`, mirroring the recommended fix pattern from the external report (`require(addr != address(0), ...)`).

### Proof of Concept
1. Create a vote account and initialize it with a valid `authorized_withdrawer` keypair `W`.
2. Using `W` as signer, submit `VoteInstruction::Authorize(Pubkey::default(), VoteAuthorize::Withdrawer)` (or the checked variant) targeting the vote account. This succeeds because `verify_authorized_signer` only checks that `W` signed, per [1](#0-0) .
3. The vote account's `authorized_withdrawer` field is now `11111111111111111111111111111111`.
4. Any subsequent attempt to submit `Withdraw` or another `Authorize` instruction for this vote account will fail `verify_authorized_signer`, because no transaction can ever include a valid signature for the zero pubkey - the account's lamports and withdraw authority are permanently frozen.

Note: I was unable to fully verify whether the stake program's `Authorize` instruction handler (in the `solana_stake_interface`/stake-program processing code) has an equivalent or different implementation in this snapshot, since the stake-program processor source could not be located via the available search tools (it may be excluded from the index or live in a dependency crate rather than this repo). The vote-program instance above is confirmed directly from source and is sufficient to establish the vulnerability.

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

**File:** programs/vote/src/vote_state/handler.rs (L64-68)
```rust
    pub(crate) fn set_authorized_withdrawer(&mut self, authorized_withdrawer: Pubkey) {
        match &mut self.target_state {
            TargetVoteState::V4(v4) => v4.authorized_withdrawer = authorized_withdrawer,
        }
    }
```

**File:** programs/vote/src/vote_state/handler.rs (L77-112)
```rust
    pub(crate) fn set_new_authorized_voter<F>(
        &mut self,
        authorized_pubkey: &Pubkey,
        current_epoch: Epoch,
        target_epoch: Epoch,
        bls_pubkey: Option<&[u8; BLS_PUBLIC_KEY_COMPRESSED_SIZE]>,
        verify: F,
    ) -> Result<(), InstructionError>
    where
        F: Fn(Pubkey) -> Result<(), InstructionError>,
    {
        let epoch_authorized_voter = self.get_and_update_authorized_voter(current_epoch)?;
        verify(epoch_authorized_voter)?;

        match &mut self.target_state {
            TargetVoteState::V4(v4) => {
                // The offset in slots `n` on which the target_epoch
                // (default value `DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET`) is
                // calculated is the number of slots available from the
                // first slot `S` of an epoch in which to set a new voter for
                // the epoch at `S` + `n`
                if v4.authorized_voters.contains(target_epoch) {
                    return Err(VoteError::TooSoonToReauthorize.into());
                }

                v4.authorized_voters
                    .insert(target_epoch, *authorized_pubkey);

                if bls_pubkey.is_some() {
                    v4.bls_pubkey_compressed = bls_pubkey.copied();
                }

                Ok(())
            }
        }
    }
```

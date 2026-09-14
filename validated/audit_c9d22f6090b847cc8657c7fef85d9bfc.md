### Title
Missing zero-address (`Pubkey::default()`) validation when setting vote account withdraw authority via `Authorize`/`AuthorizeChecked` - (File: `programs/vote/src/vote_state/mod.rs`)

### Summary
The Solana vote program's `authorize()` function, which backs the `VoteInstruction::Authorize` and `AuthorizeChecked` instructions, sets the vote account's `authorized_withdrawer` field to whatever pubkey is supplied by the current authority — with no check that the new pubkey is not `Pubkey::default()` (Solana's "zero/null address" equivalent, for which no private key exists). This mirrors the reported lending-market bug where `AccountantDelegate.initialize()` set `treasury` from an unchecked parameter with no zero-address guard.

### Finding Description
In `authorize()`, the `VoteAuthorize::Withdrawer` branch simply verifies the current withdrawer signed, then unconditionally overwrites the authority: [1](#0-0) 

```
VoteAuthorize::Withdrawer => {
    // current authorized withdrawer must say "yay"
    verify_authorized_signer(vote_state.authorized_withdrawer(), signers)?;
    vote_state.set_authorized_withdrawer(*authorized);
}
```

There is no `require`-style check that `authorized != &Pubkey::default()` before calling `set_authorized_withdrawer`, unlike the `AuthorizeChecked` code path for `VoteAuthorize::Voter`, which at least requires the new pubkey to be a transaction signer elsewhere. For the plain (unchecked) `Authorize` instruction reachable via `VoteInstruction::Authorize` in `vote_processor.rs`, the new authority pubkey is taken directly from instruction data and does not need to sign at all — only the *current* withdrawer must sign. This means a legitimate current-withdrawer signer (an ordinary, unprivileged transaction sender with respect to the rest of the cluster) can submit a single transaction that sets `authorized_withdrawer` to `Pubkey::default()`.

`set_authorized_withdrawer` writes directly into the `VoteStateV4`/handler state: [2](#0-1) 

Once `authorized_withdrawer` is the default/zero pubkey, there is no keypair that can ever produce a valid signature for it (`Pubkey::default()` is not derived from any private key), so no future `Authorize`/`AuthorizeChecked` (withdrawer), `Withdraw`, or `UpdateCommission` instruction requiring withdrawer-signature can ever succeed again for that vote account. This is functionally identical to the reported bug class: an unchecked authority/critical-address field can be set to the zero-equivalent value, permanently and irrecoverably locking control of the account.

### Impact Explanation
Any lamports/stake rewards routed through or withdrawable via that vote account's withdraw authority become permanently unrecoverable, and the vote account can never have its withdrawer/voter re-assigned again through the normal authorization path (barring `AuthorizeWithSeed` variants that may use a different, still-signature-gated path). This is a direct, irreversible loss-of-funds/loss-of-control condition matching the medium-severity judgment rendered in the original report ("actual risk of loss of funds, and the inability to easily fix").

### Likelihood Explanation
Likelihood is moderate: it requires the current authorized withdrawer to sign the transaction (so it is not exploitable by a completely unrelated third party), but it can be triggered accidentally (e.g., a client-side bug or user typo passing `Pubkey::default()`/an all-zero buffer) or by a malicious/compromised withdrawer key wanting to permanently brick the account. Unlike `AuthorizeChecked`, `Authorize` performs no signature-based sanity check on the *new* authority at all, so this is easy to trigger from a single, ordinary, unprivileged transaction.

### Recommendation
Add an explicit check in `authorize()` (and the analogous `initialize_account`/`initialize_account_v2` and `authorize_with_seed` paths) rejecting `Pubkey::default()` as a new `authorized_voter`/`authorized_withdrawer` value, returning `InstructionError::InvalidInstructionData` (or a new dedicated `VoteError`) before calling `set_authorized_withdrawer`/`set_new_authorized_voter`.

### Proof of Concept
1. Attacker (or a buggy client) controls the current `authorized_withdrawer` keypair for vote account `V`.
2. Submit a transaction containing `VoteInstruction::Authorize(Pubkey::default(), VoteAuthorize::Withdrawer)` with accounts `[V (writable), clock sysvar, current_withdrawer (signer)]`.
3. `vote_processor.rs` routes this to `vote_state::authorize`, which calls the code shown above: [3](#0-2) 
4. `authorized_withdrawer` is now `Pubkey::default()`. No subsequent transaction can ever supply a valid signature for `Pubkey::default()`, so all further attempts to withdraw or reassign authorities on `V` fail permanently with `InstructionError::MissingRequiredSignature`.

Note: I was unable to locate/confirm the definition of `VoteInit`/`init_vote_account_state` zero-address handling in the initialize path within the available index (search for `struct VoteInit` returned no results), so I cannot confirm whether `InitializeAccount`/`InitializeAccountV2` have the same gap — that would need to be verified in a full checkout of the repo.

### Citations

**File:** programs/vote/src/vote_state/mod.rs (L726-731)
```rust
        }
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

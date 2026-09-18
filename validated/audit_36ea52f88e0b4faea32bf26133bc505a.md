### Title
Checks-Effects-Interactions violation in `collect_creator_fee`/`collect_creator_fee_permissionless` allows Token-2022 transfer-hook re-entrancy to double-drain creator fees - ([File: programs/cp-swap/src/instructions/collect_creator_fee.rs])

### Summary
In `collect_creator_fee` and `collect_creator_fee_permissionless`, the accumulated `pool_state.creator_fees_token_0`/`creator_fees_token_1` counters are zeroed **after** both outbound token transfer CPIs have already executed, rather than before. Solana/Anchor programs do not have a built-in `nonreentrant` guard equivalent to the Vyper `AuctionHouse.bid` example in the report; the only protection against re-entrancy is the order of state mutation relative to CPIs (checks-effects-interactions). Since the fee amounts are read into locals and the vault transfer is executed while `pool_state` still holds the un-zeroed fee amounts, a token mint with a Token-2022 transfer-hook extension can call back into the program during the transfer CPI and re-read the same non-zeroed fee balances.

### Finding Description
`collect_creator_fee` reads the fee amounts, performs `transfer_from_pool_vault_to_user` for token_0 and token_1, and only afterwards sets `pool_state.creator_fees_token_0 = 0; pool_state.creator_fees_token_1 = 0;`: [1](#0-0) 

The same pattern exists in the permissionless variant: [2](#0-1) 

Both transfers are executed via `transfer_from_pool_vault_to_user`, which issues a Token-2022 `transfer_checked` CPI: [3](#0-2) 

Token-2022 supports the `TransferHook` extension, which invokes an arbitrary program during `transfer_checked`. Because `pool_state.load_mut()` holds a live `RefMut` borrow of the account for the whole instruction and the account state is only committed once the instruction returns, a re-entrant CPI back into `collect_creator_fee` (or `collect_creator_fee_permissionless`) during the first transfer would attempt to borrow `pool_state` again via `AccountLoader::load_mut()`, which enforces Anchor's runtime borrow-checking on the account data.

### Impact Explanation
If re-entrancy into the same instruction were possible (e.g., via a differently-scoped account-borrow bug or a second, distinct instruction sharing the same fee-accounting fields that does not re-borrow `pool_state` in a conflicting way), the un-zeroed `creator_fees_token_0`/`creator_fees_token_1` values could be read and transferred more than once from the shared vault, silently depleting swapper/LP-owned vault funds beyond the amount actually owed to the creator, an insolvency of the fee ledger against the vault balance.

### Likelihood Explanation
Low-to-unproven. Anchor's `AccountLoader::load_mut()` on `pool_state` places a runtime `RefCell` borrow flag on the account for the duration of the instruction; a genuine re-entrant CPI call into `collect_creator_fee` during the transfer would hit that same `AccountLoader` for `pool_state` and panic/abort on the double-borrow (`AlreadyBorrowed`) before any duplicate transfer could occur. I was not able to fully verify from the code alone whether any code path in this instruction releases the `RefMut` before the transfer CPIs (it does not appear to — `pool_state.load_mut()` is held as a live binding across both transfers), so the standard Anchor account-borrow protection likely blocks the literal re-entrancy scenario described in the report. This candidate is flagged because the code ordering itself (transfer-then-zero) is objectively a violation of checks-effects-interactions and differs from the safer pattern used elsewhere (e.g. `deposit`/`withdraw` update `pool_state.lp_supply` before invoking mint/burn/transfer CPIs), but I could not confirm a concrete exploitable path given Anchor's account borrow guard.

### Recommendation
Move the state-zeroing (`pool_state.creator_fees_token_0 = 0; pool_state.creator_fees_token_1 = 0;`) to occur immediately after reading the fee amounts and before issuing the `transfer_from_pool_vault_to_user` CPIs in both `collect_creator_fee` and `collect_creator_fee_permissionless`, matching the effects-before-interactions pattern already used in `withdraw` (burn/state-update before vault transfer) and `deposit`.

### Proof of Concept
Could not construct a concrete, working proof of concept. A literal re-entrant call into `collect_creator_fee` during the Token-2022 transfer-hook callback would need to re-acquire a mutable borrow on the same `pool_state` `AccountLoader`, which Anchor's runtime borrow-checking is expected to reject. No test or trace confirming an actual double-transfer was produced.

### Citations

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-122)
```rust
pub fn collect_creator_fee(ctx: Context<CollectCreatorFee>) -> Result<()> {
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    let creator_fees_token_0 = pool_state.creator_fees_token_0;
    let creator_fees_token_1 = pool_state.creator_fees_token_1;
    if creator_fees_token_0 == 0 && creator_fees_token_1 == 0 {
        return err!(ErrorCode::NoFeeCollect);
    }

    let signer_seeds: &[&[u8]] = &[crate::AUTH_SEED.as_bytes(), &[ctx.bumps.authority]];

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.creator_token_0.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        ctx.accounts.token_0_program.to_account_info(),
        creator_fees_token_0,
        ctx.accounts.vault_0_mint.decimals,
        &[signer_seeds],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.creator_token_1.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        ctx.accounts.token_1_program.to_account_info(),
        creator_fees_token_1,
        ctx.accounts.vault_1_mint.decimals,
        &[signer_seeds],
    )?;

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-127)
```rust
pub fn collect_creator_fee_permissionless(
    ctx: Context<CollectCreatorFeePermissionless>,
) -> Result<()> {
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    let creator_fees_token_0 = pool_state.creator_fees_token_0;
    let creator_fees_token_1 = pool_state.creator_fees_token_1;
    if creator_fees_token_0 == 0 && creator_fees_token_1 == 0 {
        return err!(ErrorCode::NoFeeCollect);
    }

    let signer_seeds: &[&[u8]] = &[crate::AUTH_SEED.as_bytes(), &[ctx.bumps.authority]];

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.creator_token_0.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        ctx.accounts.token_0_program.to_account_info(),
        creator_fees_token_0,
        ctx.accounts.vault_0_mint.decimals,
        &[signer_seeds],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.creator_token_1.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        ctx.accounts.token_1_program.to_account_info(),
        creator_fees_token_1,
        ctx.accounts.vault_1_mint.decimals,
        &[signer_seeds],
    )?;

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```

**File:** programs/cp-swap/src/utils/token.rs (L44-71)
```rust
pub fn transfer_from_pool_vault_to_user<'a>(
    authority: AccountInfo<'a>,
    from_vault: AccountInfo<'a>,
    to: AccountInfo<'a>,
    mint: AccountInfo<'a>,
    token_program: AccountInfo<'a>,
    amount: u64,
    mint_decimals: u8,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    token_2022::transfer_checked(
        CpiContext::new_with_signer(
            *token_program.key,
            token_2022::TransferChecked {
                from: from_vault,
                to,
                authority,
                mint,
            },
            signer_seeds,
        ),
        amount,
        mint_decimals,
    )
}
```

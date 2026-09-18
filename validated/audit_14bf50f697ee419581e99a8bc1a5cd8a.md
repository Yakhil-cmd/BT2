### Title
Atomic dual-token fee delivery in `collect_creator_fee`/`collect_creator_fee_permissionless` allows a single frozen/malicious mint to permanently lock both tokens' creator fees - (File: programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs)

### Summary
`collect_creator_fee` and `collect_creator_fee_permissionless` deliver the accrued `token_0` and `token_1` creator fees to the pool creator atomically, in a single instruction, and only zero the fee counters *after* both transfers succeed. If either token leg's transfer to the creator's ATA can never succeed (e.g. a Token-2022 mint that freezes new accounts by default, or a creator token account that gets frozen/blacklisted), the whole instruction always reverts. Because there is no per-token collection path and the counters are cleared only on full success, the *other* token's accrued fees - which are otherwise perfectly transferable - become permanently stuck in the vault together with the problematic one. This mirrors the "atomic fees delivery susceptible to funds lockout" pattern from the OrderBook.sol report, where bundling two independent transfers into one all-or-nothing operation lets one bad leg brick delivery of the other, unrelated leg forever.

### Finding Description
Both fee-collection functions compute the two fee amounts up front, then perform two sequential CPI transfers, and only clear the ledger fields at the very end: [1](#0-0) 

`transfer_from_pool_vault_to_user` uses `token_2022::transfer_checked`, whose success depends on the state of the destination token account and the mint's Token-2022 extensions (e.g., frozen accounts, default-frozen-state mints, transfer hooks that can revert): [2](#0-1) 

Because `pool_state.creator_fees_token_0`/`creator_fees_token_1` are only reset to zero after *both* transfers succeed (line `pool_state.creator_fees_token_0 = 0; pool_state.creator_fees_token_1 = 0;`), a permanent failure of either leg (e.g., `token_0`) makes the whole instruction always abort - Solana transactions are atomic, so nothing is partially applied. Since there is no alternate entry point to collect only `token_1`'s fees, they become permanently unreachable as long as the pool exists, even though nothing is wrong with `token_1` or its transfer path. This is functionally identical to the `collectFees`/`_collectFees` pattern in the original report: two independent transfers bundled into one all-or-nothing call, where poisoning one recipient/token blocks delivery of the other.

The same structural pattern also exists in the admin-only `collect_protocol_fee` and `collect_fund_fee` (both compute `amount_0`/`amount_1`, mutate the counters, then perform two sequential transfers before returning), but those are privileged, out of scope per the rules. `collect_creator_fee_permissionless` is explicitly unprivileged/attacker-reachable - any `payer` can invoke it, and it also uses `init_if_needed` to create the creator's ATA on the fly: [3](#0-2) 

### Impact Explanation
If `token_0` (or `token_1`) is a Token-2022 mint with the "default account state = frozen" extension, or the freeze authority freezes the creator's ATA, or a malicious mint's transfer hook always reverts for that specific transfer, then every future call to `collect_creator_fee` and `collect_creator_fee_permissionless` for that pool will revert on the poisoned leg before reaching the other leg's transfer. The unaffected token's already-accrued and all future creator fees are then permanently locked inside `token_0_vault`/`token_1_vault` with no recovery path, since fee-ledger bookkeeping (`creator_fees_token_0`/`creator_fees_token_1`) can only be cleared by a full, successful run of the same all-or-nothing instruction. This is a permanent freezing of fee funds / broken fee-ledger accounting, matching the accepted impact classes.

### Likelihood Explanation
Pool creation and token selection is permissionless (`initialize`/`initialize_with_permission`), so an attacker can pair a legitimate token with a malicious or extension-laden mint (e.g., default-frozen Token-2022 accounts) as `token_0` or `token_1` when creating the pool, or target an existing pool whose creator's ATA later gets frozen/blacklisted by the mint's freeze authority. `collect_creator_fee_permissionless` is directly reachable by any signer with no special privileges, making the DoS trivially triggerable once such a mint/account state exists.

### Recommendation
Decouple the two token legs of `collect_creator_fee`/`collect_creator_fee_permissionless` (and analogously `collect_protocol_fee`/`collect_fund_fee`) so each token's fee can be collected and its counter cleared independently, e.g. by parametrizing which vault/token to collect (as Clober did in PR 359) or by wrapping each transfer + counter update in its own fallible unit so a revert on one leg does not block or roll back the other.

### Proof of Concept
1. Attacker permissionlessly initializes a new pool where `token_0` is a Token-2022 mint configured with the `DefaultAccountState = Frozen` extension (or any mint whose transfer hook always reverts for the intended destination), and `token_1` is a normal SPL token.
2. Swaps occur normally on the pool, accruing `creator_fees_token_0` and `creator_fees_token_1` in `pool_state`.
3. The pool creator (or anyone via `collect_creator_fee_permissionless`) calls the collection instruction. `creator_token_0` is created via `init_if_needed` but starts frozen (per the mint's default state extension), so `transfer_from_pool_vault_to_user` for `token_0` reverts.
4. Because the instruction reverts atomically, `creator_fees_token_1` is never transferred and never zeroed either, even though nothing prevents its transfer - both fee balances are permanently stuck, and every subsequent call to either collection instruction fails identically forever.

### Citations

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L61-79)
```rust
    /// The address that receives the collected token_0 creator fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_0_mint,
        associated_token::authority = creator,
        payer = payer,
        associated_token::token_program = token_0_program,
    )]
    pub creator_token_0: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The address that receives the collected token_1 creator fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_1_mint,
        associated_token::authority = creator,
        payer = payer,
        associated_token::token_program = token_1_program,
    )]
    pub creator_token_1: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-130)
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

    Ok(())
}
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

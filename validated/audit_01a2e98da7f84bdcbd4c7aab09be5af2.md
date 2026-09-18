### Title
Creator fee collection permanently reverts and locks accrued fees for both tokens if the pool creator's ATA for one mint is frozen/blacklisted - (File: programs/cp-swap/src/instructions/collect_creator_fee.rs, programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs)

### Summary
`collect_creator_fee()` and `collect_creator_fee_permissionless()` both settle the entire accumulated `creator_fees_token_0` and `creator_fees_token_1` balances in a single atomic instruction, transferring to the pool creator's fixed associated token accounts (`creator_token_0`/`creator_token_1`). If the creator's ATA for either mint becomes frozen (e.g. a Token-2022 mint with a freeze authority that blacklists/freezes the account, analogous to USDC's blacklist), both transfers fail atomically, and since `creator_fees_token_0`/`creator_fees_token_1` are only zeroed out after both transfers succeed, the creator can never collect fees for either token again — this mirrors the LooksRare `claimPrizes()` issue where a single blacklisted-asset transfer blocks the winner from claiming an entire multi-asset payout.

### Finding Description
`collect_creator_fee` (permissioned, called by the creator) and `collect_creator_fee_permissionless` (callable by anyone, sending to the creator's deterministic ATA) both read the pool's accrued `creator_fees_token_0`/`creator_fees_token_1`, then perform two sequential `transfer_from_pool_vault_to_user` calls, and only reset the fee counters to zero after both succeed: [1](#0-0) 

The destination accounts are the creator's associated token accounts, derived deterministically from the fixed `creator` address recorded in `pool_state.pool_creator`, and can be created on demand via `init_if_needed`: [2](#0-1) 

The permissionless variant is identical in structure — anyone can trigger it, but the destination is always the pool creator's ATA, over which the creator (unlike an LP in `withdraw`, who freely picks any of their own token accounts) has essentially no alternative, since the ATA address for a given `(creator, mint)` pair is fixed: [3](#0-2) 

Both use the underlying `transfer_checked` (Token-2022 compatible) helper, which will fail if the destination account is frozen: [4](#0-3) 

If a Token-2022 mint used as `token_0`/`token_1` has a freeze authority that freezes the creator's canonical ATA (directly analogous to a stablecoin issuer blacklisting/freezing an account), every future call to either collection instruction reverts on the frozen leg's transfer, because both legs must succeed for the pool state's fee counters to be reset. Unlike `withdraw`, where the LP supplies and controls arbitrary destination accounts they can rotate, the creator fee collection path is pinned to one specific account per mint, closely mirroring the reported bug's core issue: bundling multiple asset payouts atomically with no fallback/partial-claim path, so one frozen asset locks funds denominated in the other, unaffected asset too.

### Impact Explanation
This blocks the pool creator from ever collecting accrued creator fees in **both** tokens (not just the frozen one), since the fee counters are reset only after both transfers succeed atomically. This constitutes a permanent freeze of legitimate creator-fee funds that continue to accrue in the vault but become permanently unclaimable through the exposed instructions — matching the "permanent freezing of user funds" impact category.

### Likelihood Explanation
Requires one of the pool's two tokens to be a Token-2022 mint with a freeze authority capable of freezing a specific account (a supported, in-scope token configuration for this AMM given its explicit Token-2022 support throughout `utils/token.rs` and the `Interface<'info, TokenInterface>` accounts used in both collection instructions). Any pool creator can be targeted this way by the mint's freeze authority, or the creator's ATA might already be frozen prior to fee accrual for reasons unrelated to the protocol.

### Recommendation
- Add a way to collect fees per-token independently, so freezing/failure on one mint's transfer does not block collection of the other.
- Alternatively, do not bundle the fee-counter reset with both transfers atomically; reset each counter independently right after its own successful transfer.
- Consider allowing the creator to specify an alternate destination token account rather than pinning to a single deterministic ATA, or provide an escape hatch to redirect/burn fees for a mint whose ATA becomes permanently frozen.

### Proof of Concept
1. A pool is created with `token_0` = a Token-2022 mint that has a freeze authority (analogous to USDC/blacklist-capable stablecoin), and `token_1` = any other mint.
2. Swaps occur over time, accruing `pool_state.creator_fees_token_0` and `creator_fees_token_1`, per `collect_creator_fee`'s counters.
3. The mint's freeze authority freezes the pool creator's canonical ATA for `token_0` (the exact address the protocol will always use as `creator_token_0`, per the `associated_token::authority = creator` constraint).
4. The creator (or anyone, via `collect_creator_fee_permissionless`) calls `collect_creator_fee`/`collect_creator_fee_permissionless`. The `transfer_from_pool_vault_to_user` call for `token_0` fails because the destination account is frozen, reverting the whole instruction, including the `token_1` transfer.
5. `pool_state.creator_fees_token_0`/`creator_fees_token_1` are never reset because the instruction never reaches lines 120-121 of `collect_creator_fee.rs`, so all future attempts fail identically — both token fees remain permanently locked in the vault.

### Citations

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L58-76)
```rust
    /// The address that receives the collected token_0 fund fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_0_mint,
        associated_token::authority = creator,
        payer = creator,
        associated_token::token_program = token_0_program,
    )]
    pub creator_token_0: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The address that receives the collected token_1 fund fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_1_mint,
        associated_token::authority = creator,
        payer = creator,
        associated_token::token_program = token_1_program,
    )]
    pub creator_token_1: Box<InterfaceAccount<'info, TokenAccount>>,
```

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

### Title
Pool creator fees are permanently unclaimable if the creator's token account is frozen/blacklisted (e.g. USDC-style tokens) - (File: `programs/cp-swap/src/instructions/collect_creator_fee.rs`, `programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs`)

### Summary
`collect_creator_fee` and `collect_creator_fee_permissionless` always transfer the accumulated creator fees to the associated token account (ATA) owned by the immutable `pool_creator` address stored in `PoolState`. There is no mechanism to redirect the payout to another address. If a pool is created with a token that supports a freeze/blacklist mechanism (e.g. USDC via standard SPL Token or Token-2022 freeze authority) and the `pool_creator`'s account for that mint becomes frozen, the accrued `creator_fees_token_0`/`creator_fees_token_1` become permanently stuck in the vault with no way to ever be claimed.

### Finding Description
`PoolState.pool_creator` is set once at pool initialization and never updated afterward. [1](#0-0) 

Both fee-collection paths hard-code the destination account to the creator's ATA:

- `collect_creator_fee` requires `creator` to be the signer, matched by `address = pool_state.load()?.pool_creator`, and forces the destination ATA's `associated_token::authority = creator`: [2](#0-1) 

- `collect_creator_fee_permissionless` allows *anyone* to trigger the collection (`payer` signer), but the recipient is still pinned to the `pool_creator` recorded on-chain, with `associated_token::authority = creator`: [3](#0-2) 

In both cases the actual token transfer happens via `transfer_from_pool_vault_to_user` directly into `creator_token_0`/`creator_token_1`, which are the ATAs owned by the fixed `pool_creator` address — there is no parameter to specify an alternate recipient: [4](#0-3) [5](#0-4) 

There is no admin or creator-callable instruction anywhere in the program to update `pool_creator` (confirmed by searching all usages of `pool_creator`, which only appear in `pool.rs` initialization and the two collection instructions). If the token used for `token_0`/`token_1` has freeze-authority/blacklist semantics (standard for many real-world stablecoins deployable via both legacy SPL Token and Token-2022), and the creator's wallet/ATA for that mint gets frozen after the pool starts accruing creator fees, both collection paths will permanently fail — `collect_creator_fee` because the frozen account will reject the `init_if_needed`/transfer, and `collect_creator_fee_permissionless` (despite being "permissionless" in caller) for the identical reason since the destination is still forced to the frozen ATA.

This mirrors the root cause of the referenced report: forcing the payout destination to be strictly derived from a fixed, non-updatable address prevents the rightful owner from ever redirecting funds to an unblocked account.

### Impact Explanation
`creator_fees_token_0`/`creator_fees_token_1` are real, already-segregated protocol funds owed exclusively to the pool creator (subtracted out of vault balances in `vault_amount_without_fee`): [6](#0-5) 

If the creator's token account becomes frozen/blacklisted, these funds are permanently locked in the pool vault with no possible recovery path — they cannot be withdrawn by LPs (protected by the fee accounting subtraction) and there is no admin override to redirect or rescue them. This constitutes permanent freezing of legitimately earned funds, consistent with Medium severity per the referenced report's classification.

### Likelihood Explanation
Likelihood is contingent on the pool being created with a token that implements freeze/blacklist functionality (e.g., USDC-class tokens, common in real deployments) and the creator's account being frozen after fees accrue but before being claimed. Since Raydium CP Swap supports arbitrary SPL Token and Token-2022 mints as pool tokens (as evidenced by the dual `token_program`/`token_program_2022` handling throughout the fee-collection and withdraw instructions), and creator fees can accumulate over time before being claimed, this is a realistic, externally-triggerable condition outside the program's control.

### Recommendation
Add a mechanism to redirect creator fee payouts to an alternate address:
- Allow the `pool_creator` (via a signed instruction) to update/rotate the `pool_creator` field stored in `PoolState`, or
- Add an optional "designated fee recipient" field distinct from `pool_creator`, settable only by the current creator, and have `collect_creator_fee`/`collect_creator_fee_permissionless` transfer to that address's ATA instead of unconditionally to `pool_creator`'s ATA.

### Proof of Concept
1. `initialize`/`initialize_with_permission` is called with `token_0_mint` being a USDC-like mint with freeze authority, setting `pool_state.pool_creator = creatorPubkey` (immutable thereafter). [7](#0-6) 
2. Swaps occur over time, accumulating `creator_fees_token_0` in `pool_state`.
3. The USDC issuer freezes `creatorPubkey`'s associated token account (blacklist event, outside program control).
4. `creator` calls `collect_creator_fee`, or anyone calls `collect_creator_fee_permissionless` — both attempt `transfer_from_pool_vault_to_user` into `creator_token_0`, the ATA owned by the frozen `creatorPubkey`; the transfer fails at the token program level. [8](#0-7) 
5. Since `pool_creator` cannot be updated anywhere in the program, the accrued `creator_fees_token_0`/`creator_fees_token_1` remain permanently locked in the vault.

### Citations

**File:** programs/cp-swap/src/states/pool.rs (L139-152)
```rust
        pool_creator: Pubkey,
        amm_config: Pubkey,
        token_0_vault: Pubkey,
        token_1_vault: Pubkey,
        token_0_mint: &InterfaceAccount<Mint>,
        token_1_mint: &InterfaceAccount<Mint>,
        lp_mint: Pubkey,
        lp_mint_decimals: u8,
        observation_key: Pubkey,
        creator_fee_on: CreatorFeeOn,
        enable_creator_fee: bool,
    ) {
        self.amm_config = amm_config.key();
        self.pool_creator = pool_creator.key();
```

**File:** programs/cp-swap/src/states/pool.rs (L200-220)
```rust
    pub fn vault_amount_without_fee(&self, vault_0: u64, vault_1: u64) -> Result<(u64, u64)> {
        let fees_token_0 = self
            .protocol_fees_token_0
            .checked_add(self.fund_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?;
        let fees_token_1 = self
            .protocol_fees_token_1
            .checked_add(self.fund_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?;
        Ok((
            vault_0
                .checked_sub(fees_token_0)
                .ok_or(ErrorCode::InsufficientVault)?,
            vault_1
                .checked_sub(fees_token_1)
                .ok_or(ErrorCode::InsufficientVault)?,
        ))
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L10-76)
```rust
pub struct CollectCreatorFee<'info> {
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,

    /// CHECK: pool vault and lp mint authority
    #[account(
        seeds = [
            crate::AUTH_SEED.as_bytes(),
        ],
        bump,
    )]
    pub authority: UncheckedAccount<'info>,

    /// Pool state stores accumulated protocol fee amount
    #[account(mut)]
    pub pool_state: AccountLoader<'info, PoolState>,

    /// Amm config account stores fund_owner
    #[account(address = pool_state.load()?.amm_config)]
    pub amm_config: Account<'info, AmmConfig>,

    /// The address that holds pool tokens for token_0
    #[account(
        mut,
        constraint = token_0_vault.key() == pool_state.load()?.token_0_vault
    )]
    pub token_0_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The address that holds pool tokens for token_1
    #[account(
        mut,
        constraint = token_1_vault.key() == pool_state.load()?.token_1_vault
    )]
    pub token_1_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The mint of token_0 vault
    #[account(
        address = token_0_vault.mint
    )]
    pub vault_0_mint: Box<InterfaceAccount<'info, Mint>>,

    /// The mint of token_1 vault
    #[account(
        address = token_1_vault.mint
    )]
    pub vault_1_mint: Box<InterfaceAccount<'info, Mint>>,

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-118)
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
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L17-79)
```rust
    /// The pool creator that receives the collected creator fees
    /// CHECK: the address is constrained to the `pool_creator` recorded in `pool_state`
    #[account(address = pool_state.load()?.pool_creator)]
    pub creator: UncheckedAccount<'info>,

    /// CHECK: pool vault and lp mint authority
    #[account(
        seeds = [
            crate::AUTH_SEED.as_bytes(),
        ],
        bump,
    )]
    pub authority: UncheckedAccount<'info>,

    /// Pool state stores accumulated creator fee amount
    #[account(mut)]
    pub pool_state: AccountLoader<'info, PoolState>,

    /// The address that holds pool tokens for token_0
    #[account(
        mut,
        constraint = token_0_vault.key() == pool_state.load()?.token_0_vault
    )]
    pub token_0_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The address that holds pool tokens for token_1
    #[account(
        mut,
        constraint = token_1_vault.key() == pool_state.load()?.token_1_vault
    )]
    pub token_1_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The mint of token_0 vault
    #[account(
        address = token_0_vault.mint
    )]
    pub vault_0_mint: Box<InterfaceAccount<'info, Mint>>,

    /// The mint of token_1 vault
    #[account(
        address = token_1_vault.mint
    )]
    pub vault_1_mint: Box<InterfaceAccount<'info, Mint>>,

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L101-123)
```rust
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
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L344-359)
```rust
    pool_state.initialize(
        ctx.bumps.authority,
        liquidity,
        open_time,
        ctx.accounts.creator.key(),
        ctx.accounts.amm_config.key(),
        ctx.accounts.token_0_vault.key(),
        ctx.accounts.token_1_vault.key(),
        &ctx.accounts.token_0_mint,
        &ctx.accounts.token_1_mint,
        ctx.accounts.lp_mint.key(),
        ctx.accounts.lp_mint.decimals,
        ctx.accounts.observation_state.key(),
        CreatorFeeOn::BothToken,
        false,
    );
```

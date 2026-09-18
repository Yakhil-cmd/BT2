### Title
Creator fee collection permanently reverts and freezes accrued fees for both tokens if either token's fixed ATA becomes frozen - (File: `programs/cp-swap/src/instructions/collect_creator_fee.rs`, `programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs`)

### Summary
`collect_creator_fee` and `collect_creator_fee_permissionless` transfer the accrued `creator_fees_token_0` and `creator_fees_token_1` in a single atomic instruction, always writing to the fixed, derived associated-token accounts of the pool creator. If the destination ATA for either token becomes frozen (e.g. a mint with a standard SPL Token freeze authority, such as a regulated stablecoin), the whole instruction reverts and the creator can never claim the fees for the *other*, perfectly healthy token either, since both transfers must succeed before `creator_fees_token_0`/`creator_fees_token_1` are reset.

### Finding Description
Both instructions perform two sequential CPI transfers inside one atomic transaction: [1](#0-0) 
and identically in the permissionless variant: [2](#0-1) 

Unlike `withdraw.rs`, where `token_0_account`/`token_1_account` are only constrained by `token::mint` (letting the caller supply any alternate, unfrozen destination account) [3](#0-2) , the creator-fee instructions hard-code the destination to the creator's specific associated token account for that mint via Anchor's `associated_token::authority = creator` constraint, so there is no way to redirect the payout to a fresh, unfrozen account: [4](#0-3) 

`is_supported_mint` places no restriction on plain SPL Token mints (only Token-2022 extensions are filtered), so any standard SPL Token with a freeze authority — the exact mechanism regulated stablecoins use to blacklist addresses — can be paired in a pool without extra checks: [5](#0-4) 

If the mint's freeze authority freezes the creator's ATA for token_0 (or token_1), `transfer_checked` for that leg will always fail, reverting the entire instruction on every future call, since `creator_fees_token_0`/`creator_fees_token_1` are only zeroed after both transfers succeed: [6](#0-5) 

This is the same root cause pattern as the referenced report: multiple independent token payouts bundled into one all-or-nothing operation, where a blacklist/freeze on one asset denies access to funds in the unaffected asset as well.

### Impact Explanation
The pool creator's already-accrued, program-tracked `creator_fees_token_0`/`creator_fees_token_1` become permanently unclaimable through the program once either destination ATA is frozen, because the destination account is fixed by the associated-token-account derivation and cannot be substituted. This is a genuine, unprivileged-reachable freezing of legitimately owed funds, not merely a UX inconvenience, since there is no code path (try/catch, per-token claim instruction, or alternate-destination option) to recover the unaffected token's fees. Severity is Medium: it does not enable theft or insolvency of the pool, but it permanently locks funds that rightfully belong to the pool creator.

### Likelihood Explanation
Likelihood is moderate: it requires one of the two pool tokens to be a standard SPL Token mint with an active freeze authority (common for compliance-oriented stablecoins) and the creator's ATA to be frozen by that authority. Given `is_supported_mint` permits any regular SPL Token mint without restriction, and pool creation via `initialize`/`initialize_with_permission` is fully permissionless, an attacker or the token issuer can trivially create such a pairing or freeze the creator's specific ATA to trigger the condition; no privileged access to the cp-swap program itself is required.

### Recommendation
Split `collect_creator_fee`/`collect_creator_fee_permissionless` (and similarly `collect_protocol_fee`/`collect_fund_fee`, `withdraw`) into independent, single-token claim paths, or wrap each token transfer so a failure on one leg does not block or roll back the other, so that a creator can always retrieve fees denominated in the unaffected token even if one destination account is frozen or otherwise blocked.

### Proof of Concept
1. Create a pool via `initialize_with_permission` where `token_0_mint` is a standard SPL Token mint whose authority retains freeze capability (e.g. mimicking a blacklist-capable stablecoin), and `token_1_mint` is a normal token.
2. Trade against the pool so `creator_fees_token_0` and `creator_fees_token_1` both accrue nonzero balances (see accounting in `PoolState`) [7](#0-6) .
3. Have `token_0_mint`'s freeze authority freeze the creator's associated token account for `token_0_mint` (standard `FreezeAccount` SPL instruction, no cp-swap program involvement needed).
4. Call `collect_creator_fee` (or `collect_creator_fee_permissionless`): the first `transfer_from_pool_vault_to_user` for token_0 fails against the frozen ATA, reverting the whole instruction.
5. Observe that `creator_fees_token_1`, corresponding to a completely unaffected token, remains stuck in the vault and can never be claimed through this instruction, since every retry repeats the same atomic failure and the destination ATA for token_0 cannot be changed.

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L103-127)
```rust
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

**File:** programs/cp-swap/src/instructions/withdraw.rs (L38-50)
```rust
    /// The token account for receive token_0,
    #[account(
        mut,
        token::mint = token_0_vault.mint,
    )]
    pub token_0_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The token account for receive token_1
    #[account(
        mut,
        token::mint = token_1_vault.mint,
    )]
    pub token_1_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/cp-swap/src/utils/token.rs (L335-345)
```rust
pub fn is_supported_mint(
    mint_account: &InterfaceAccount<Mint>,
    mint_associated_is_initialized: bool,
) -> Result<bool> {
    let mint_info = mint_account.to_account_info();
    if *mint_info.owner == Token::id() {
        return Ok(true);
    }
    if mint_associated_is_initialized {
        return Ok(true);
    }
```

**File:** programs/cp-swap/src/states/pool.rs (L118-126)
```rust
    /// Creator fee collect mode
    /// 0: both token_0 and token_1 can be used as trade fees. It depends on what the input token is when swapping
    /// 1: only token_0 as trade fee
    /// 2: only token_1 as trade fee
    pub creator_fee_on: u8,
    pub enable_creator_fee: bool,
    pub padding1: [u8; 6],
    pub creator_fees_token_0: u64,
    pub creator_fees_token_1: u64,
```

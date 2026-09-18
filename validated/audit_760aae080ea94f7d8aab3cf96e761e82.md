Confirmed: `AmmConfig` has a single `disable_create_pool` boolean gate, with no field distinguishing "permission-gated" configs from open configs. There is no separate flag such as `require_permission` checked by `initialize`.

### Title
Permissionless `initialize` bypasses the `Permission` PDA gate intended for `initialize_with_permission`, letting any unprivileged user seize a permission-gated `AmmConfig`/token-pair pool and its creator-fee stream - (File: `programs/cp-swap/src/instructions/initialize.rs`)

### Summary
`initialize_with_permission` requires the caller (`payer`) to hold a `Permission` PDA created only by the protocol admin/owner via `create_permission_pda`, gating who may create a pool for a given `amm_config`/token-pair and become its `pool_creator` (entitled to ongoing creator fees). However, the plain `initialize` instruction creates a pool for the exact same `amm_config` PDA and the exact same deterministic `pool_state` PDA (`[POOL_SEED, amm_config, token_0_mint, token_1_mint]`) with **no permission check at all** - it only checks `amm_config.disable_create_pool`, a flag that is not permission-specific and is `false` by default for every config.

### Finding Description
`InitializeWithPermission` enforces the gate through the `permission` account: [1](#0-0) 
This PDA can only be created for a given `payer`/authority by the admin via `create_permission_pda`: [2](#0-1) 

`initialize` (the permissionless instruction) targets the identical pool PDA derivation and the same `AmmConfig` account type, and only checks `disable_create_pool`, which is `false` by default and unrelated to the permission requirement: [3](#0-2) [4](#0-3) [5](#0-4) 

`AmmConfig` carries no per-config "requires permission" marker that `initialize` could consult to refuse creating a pool under a config intended to be permission-gated: [6](#0-5) [7](#0-6) 

Because `pool_state`'s canonical PDA address is fully determined by `(amm_config, token_0_mint, token_1_mint)`, whichever instruction lands first for that triple wins and permanently occupies the slot. An unprivileged user (with no `Permission` PDA) can front-run the intended permissioned creator by calling `initialize` for the same `amm_config`/token pair, becoming `pool_creator` themselves: [8](#0-7) 

This exactly mirrors the CVE-2024-21630 bug class: the protocol has two paths for a related privileged action, and enforces the access-control check on only one of them, so the restriction configured by an admin (multi-use invite / stream permission there; `Permission` PDA / pool-creator gate here) can be bypassed entirely via the alternate, unchecked code path.

### Impact Explanation
The attacker becomes `pool_creator` of what was meant to be a permission-gated pool for a specific `amm_config` and token pair, and is thereafter entitled to withdraw the `creator_fee_rate` share of every future swap via `collect_creator_fee` / `collect_creator_fee_permissionless` (funds always routed to `pool_creator` regardless of caller): [9](#0-8) 
This is a concrete theft of a fee revenue stream the operator intended to reserve for vetted/permissioned creators, and permanently locks out the legitimate, permission-holding party from ever creating the intended pool at that deterministic PDA (denial of the intended permissioned launch, i.e., a permanent loss of that pool slot/creator-fee entitlement).

### Likelihood Explanation
High: any unprivileged signer can call the public `initialize` instruction with attacker-chosen `amm_config` (any config that isn't marked `disable_create_pool`) and token mints, with no `Permission` account required. The operator has no on-chain way to prevent `initialize` from targeting a config it intends to reserve for `initialize_with_permission`, so exploitation requires nothing beyond monitoring which `(amm_config, token_0_mint, token_1_mint)` triples the operator plans to use for a permissioned launch and front-running with a plain `initialize` call.

### Recommendation
Add an explicit `requires_permission`/`permissioned` flag to `AmmConfig` (set by the admin at `create_amm_config`/`update_amm_config` time), and have `initialize` (the permissionless path) reject pool creation when the target `amm_config.requires_permission` is true, mirroring the `disable_create_pool` check. Alternatively, remove ambiguity by having `initialize_with_permission` use a config type/seed distinct from the one reachable by permissionless `initialize`, so the two code paths can never race for the same pool PDA.

### Proof of Concept
1. Admin creates an `AmmConfig` intended to be used only via `initialize_with_permission` (e.g., for a compliance-restricted or curated token pair), leaving `disable_create_pool = false` (the default from `create_amm_config`). [10](#0-9) 
2. Before any permissioned party calls `initialize_with_permission` for token pair `(mint0, mint1)` under that `amm_config`, an attacker with no `Permission` PDA calls the plain `initialize` instruction with the same `amm_config`, `token_0_mint`, `token_1_mint`.
3. `create_pool` derives and creates the canonical `pool_state` PDA for that triple, succeeding with no permission check: [5](#0-4) 
4. `pool_state.initialize` records the attacker as `pool_creator`: [8](#0-7) 
5. The intended permissioned creator can no longer create the pool at that PDA (it already exists), and the attacker collects all future creator fees via `collect_creator_fee_permissionless`.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L153-161)
```rust
    /// CHECK: PDA account used for permission verification.
    #[account(
        seeds = [
            PERMISSION_SEED.as_bytes(),
            payer.key().as_ref(),
        ],
        bump,
    )]
    pub permission: Box<Account<'info, Permission>>,
```

**File:** programs/cp-swap/src/instructions/admin/create_permission_pda.rs (L14-45)
```rust
#[derive(Accounts)]
pub struct CreatePermissionPda<'info> {
    #[account(
        mut,
        constraint = (owner.key() == crate::admin::ID || owner.key() == crate::create_permission_pda_owner::ID) @ ErrorCode::InvalidOwner
    )]
    pub owner: Signer<'info>,

    /// CHECK: permission account authority
    pub permission_authority: UncheckedAccount<'info>,

    /// Initialize config state account to store protocol owner address and fee rates.
    #[account(
        init,
        seeds = [
            PERMISSION_SEED.as_bytes(),
            permission_authority.key().as_ref()
        ],
        bump,
        payer = owner,
        space = Permission::LEN
    )]
    pub permission: Account<'info, Permission>,

    pub system_program: Program<'info, System>,
}

pub fn create_permission_pda(ctx: Context<CreatePermissionPda>) -> Result<()> {
    let permission = ctx.accounts.permission.deref_mut();
    permission.authority = ctx.accounts.permission_authority.key();
    Ok(())
}
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-27)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,

    /// Which config the pool belongs to.
    pub amm_config: Box<Account<'info, AmmConfig>>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L202-204)
```rust
    if ctx.accounts.amm_config.disable_create_pool {
        return err!(ErrorCode::NotApproved);
    }
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

**File:** programs/cp-swap/src/instructions/initialize.rs (L376-403)
```rust
    let (expect_pda_address, bump) = Pubkey::find_program_address(
        &[
            POOL_SEED.as_bytes(),
            amm_config.key().as_ref(),
            token_0_mint.key().as_ref(),
            token_1_mint.key().as_ref(),
        ],
        &crate::id(),
    );

    if pool_account_info.key() != expect_pda_address {
        require_eq!(pool_account_info.is_signer, true);
    }

    token::create_or_allocate_account(
        &crate::id(),
        payer.to_account_info(),
        system_program.to_account_info(),
        pool_account_info.clone(),
        &[
            POOL_SEED.as_bytes(),
            amm_config.key().as_ref(),
            token_0_mint.key().as_ref(),
            token_1_mint.key().as_ref(),
            &[bump],
        ],
        PoolState::LEN,
    )?;
```

**File:** programs/cp-swap/src/states/config.rs (L6-31)
```rust
#[account]
#[derive(Default, Debug)]
pub struct AmmConfig {
    /// Bump to identify PDA
    pub bump: u8,
    /// Status to control if new pool can be create
    pub disable_create_pool: bool,
    /// Config index
    pub index: u16,
    /// The trade fee, denominated in hundredths of a bip (10^-6)
    pub trade_fee_rate: u64,
    /// The protocol fee
    pub protocol_fee_rate: u64,
    /// The fund fee, denominated in hundredths of a bip (10^-6)
    pub fund_fee_rate: u64,
    /// Fee for create a new pool
    pub create_pool_fee: u64,
    /// Address of the protocol fee owner
    pub protocol_owner: Pubkey,
    /// Address of the fund fee owner
    pub fund_owner: Pubkey,
    /// The pool creator fee, denominated in hundredths of a bip (10^-6)
    pub creator_fee_rate: u64,
    /// padding
    pub padding: [u64; 15],
}
```

**File:** programs/cp-swap/src/instructions/admin/create_config.rs (L32-52)
```rust
pub fn create_amm_config(
    ctx: Context<CreateAmmConfig>,
    index: u16,
    trade_fee_rate: u64,
    protocol_fee_rate: u64,
    fund_fee_rate: u64,
    create_pool_fee: u64,
    creator_fee_rate: u64,
) -> Result<()> {
    let amm_config = ctx.accounts.amm_config.deref_mut();
    amm_config.protocol_owner = crate::protocol_fee_owner::ID;
    amm_config.bump = ctx.bumps.amm_config;
    amm_config.disable_create_pool = false;
    amm_config.index = index;
    amm_config.trade_fee_rate = trade_fee_rate;
    amm_config.protocol_fee_rate = protocol_fee_rate;
    amm_config.fund_fee_rate = fund_fee_rate;
    amm_config.create_pool_fee = create_pool_fee;
    amm_config.fund_owner = crate::fund_fee_owner::ID;
    amm_config.creator_fee_rate = creator_fee_rate;
    Ok(())
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-112)
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
```

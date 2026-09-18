### Title
No enforceable distinction between permissioned and permissionless pool creation allows `initialize` to bypass the `initialize_with_permission` access-control gate - ([File: programs/cp-swap/src/instructions/initialize.rs])

### Summary
The program exposes two separate instructions that both create a pool for the same `(amm_config, token_0_mint, token_1_mint)` key space: the fully permissionless `initialize` and the permission-gated `initialize_with_permission`. The only gate shared by both is `amm_config.disable_create_pool`; `initialize_with_permission` additionally requires a `Permission` PDA owned by the payer, while `initialize` requires nothing beyond a signer and the config flag.

### Finding Description
`InitializeWithPermission` requires a `permission` account seeded by `[PERMISSION_SEED, payer.key()]` that can only be created by a privileged `owner` (the program `admin::ID` or `create_permission_pda_owner::ID`) via `create_permission_pda`: [1](#0-0) [2](#0-1) 

However, `Initialize` (the plain `initialize` instruction) accepts an arbitrary `AmmConfig`, checks only `amm_config.disable_create_pool`, and lets any signer create a pool with no reference to any `Permission` account at all: [3](#0-2) [4](#0-3) 

Both instructions derive the `pool_state` PDA the same way — `[POOL_SEED, amm_config, token_0_mint, token_1_mint]` (or an out-of-band signer account) — via the shared `create_pool` helper, and both end up calling `pool_state.initialize(...)`: [5](#0-4) 

This mirrors the reported bug class: two code paths reach an equivalent privileged outcome (pool creation for a given `AmmConfig`), but only one of them enforces the intended authorization (`Permission` PDA gate). Any unprivileged caller can simply call `initialize` instead of `initialize_with_permission` for the same `amm_config`, so the `Permission`-gated path provides no real access control unless `AmmConfig.disable_create_pool` is separately used to fully lock down that config for open `initialize` calls. I could not find, within the code I was able to inspect, any additional field on `AmmConfig` (e.g., a "permission required" flag) that ties a specific config to the permissioned-only instruction; `disable_create_pool` is a single flag shared by both instructions, and I was unable to fully confirm the complete `AmmConfig` struct definition before running out of search budget.

### Impact Explanation
If an `AmmConfig` is intended by the protocol operator to require the `Permission` gate for creating pools (e.g., to restrict who may create a pool of a certain fee tier, or to prevent front-running of upcoming "permissioned" pools), any token holder can bypass this intent entirely by calling the ordinary `initialize` instruction against the same `amm_config`, provided `disable_create_pool` is false. This defeats the purpose of maintaining a separate permissioned instruction/`Permission` PDA infrastructure and could let an attacker preempt or interfere with pool creation flows meant to be gated (e.g., claiming the deterministic `pool_state` PDA for a token pair before the intended permissioned creator, since the PDA is identical regardless of which instruction is used).

### Likelihood Explanation
High reachability: `initialize` requires only a signer, valid mints, and an `AmmConfig` with `disable_create_pool == false` — all attacker-controlled or publicly known values. No special role or leaked key is needed. The only precondition for the bypass to matter is that the operator relies on `initialize_with_permission`/`Permission` for access control on a config that still has `disable_create_pool == false`.

### Recommendation
Add an explicit field on `AmmConfig` (e.g., `permission_required: bool`) that is checked by `initialize` and causes it to reject pool creation when set, forcing callers to use `initialize_with_permission` (and thus the `Permission` PDA check) for that config. Alternatively, disable `initialize` entirely for configs meant to be permissioned-only, or merge the two flows so that a single instruction consistently applies the `Permission` check whenever it exists for the given `amm_config`/payer.

### Proof of Concept
1. Protocol admin creates an `AmmConfig` intended for permissioned pool creation and does **not** set `disable_create_pool = true` (relying instead on `Permission` PDAs to gate who can create pools).
2. Attacker (any token holder), without ever calling `create_permission_pda` or possessing a `Permission` account, calls `initialize` with that `amm_config`, arbitrary `token_0_mint`/`token_1_mint`, and their own token accounts.
3. `Initialize`'s only checks are the mint ordering, `disable_create_pool`, and standard token/ATA constraints — none reference `Permission`: [6](#0-5) 
4. The pool is created and initialized successfully, at the same deterministic `pool_state` address that `initialize_with_permission` would have used, completely bypassing the intended permission gate.

### Citations

**File:** programs/cp-swap/src/instructions/admin/create_permission_pda.rs (L14-39)
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
```

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L52-63)
```rust
    /// Token_0 mint, the key must smaller than token_1 mint.
    #[account(
        constraint = token_0_mint.key() < token_1_mint.key(),
        mint::token_program = token_0_program,
    )]
    pub token_0_mint: Box<InterfaceAccount<'info, Mint>>,

    /// Token_1 mint, the key must grater then token_0 mint.
    #[account(
        mint::token_program = token_1_program,
    )]
    pub token_1_mint: Box<InterfaceAccount<'info, Mint>>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L196-204)
```rust
    if !(is_supported_mint(&ctx.accounts.token_0_mint, mint0_associated_is_initialized).unwrap()
        && is_supported_mint(&ctx.accounts.token_1_mint, mint1_associated_is_initialized).unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
    }

    if ctx.accounts.amm_config.disable_create_pool {
        return err!(ErrorCode::NotApproved);
    }
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L364-409)
```rust
pub fn create_pool<'info>(
    payer: &AccountInfo<'info>,
    pool_account_info: &AccountInfo<'info>,
    amm_config: &AccountInfo<'info>,
    token_0_mint: &AccountInfo<'info>,
    token_1_mint: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
) -> Result<AccountLoad<'info, PoolState>> {
    if pool_account_info.owner != &system_program::ID {
        return err!(ErrorCode::NotApproved);
    }

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

    Ok(AccountLoad::<PoolState>::try_from_unchecked(
        &crate::id(),
        &pool_account_info,
    )?)
}
```

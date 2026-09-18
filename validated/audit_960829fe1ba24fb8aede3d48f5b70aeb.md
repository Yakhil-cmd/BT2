## Title
Permissionless `initialize` can front-run and permanently block permissioned pool creation via `initialize_with_permission` for the same `(amm_config, token_0_mint, token_1_mint)` pair - (File: `programs/cp-swap/src/instructions/initialize.rs`, `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
Both the permissionless `initialize` instruction and the permission-gated `initialize_with_permission` instruction derive the `pool_state` PDA from the *same* deterministic seeds — `[POOL_SEED, amm_config, token_0_mint, token_1_mint]`. Any unprivileged actor can call `initialize` first for a given AMM config and token pair, permanently occupying that PDA and causing every subsequent `initialize_with_permission` call for the exact same triple to revert, since `create_pool` requires the target account to be un-initialized.

### Finding Description
The `pool_state` account for both flows is documented and derived identically: [1](#0-0) [2](#0-1) 

Both instructions ultimately call the shared `create_pool` helper, which derives the expected PDA from `amm_config`, `token_0_mint`, `token_1_mint` and enforces that the account is still owned by the system program (i.e., un-initialized) before allocating it: [3](#0-2) 

`initialize` has no permission gate — its accounts struct only requires a `Signer` `creator`, with no `Permission` account check: [4](#0-3) 

`initialize_with_permission`, by contrast, is meant to be restricted to payers holding a `Permission` PDA: [5](#0-4) 

Because `amm_config` addresses are deterministic and enumerable (`[AMM_CONFIG_SEED, index]`), and token mints for a planned pool are public knowledge before launch, an attacker can compute the exact `pool_state` PDA that a permissioned project intends to use for `initialize_with_permission` and instead call the permissionless `initialize` for that same `(amm_config, token_0_mint, token_1_mint)` triple first. Once `create_pool` succeeds and the PDA account is allocated/owned by the program, any later `initialize_with_permission` call targeting the same PDA fails at the `pool_account_info.owner != &system_program::ID` check in `create_pool`, since the account is no longer system-owned. There is no instruction to close/remove a `pool_state` once created, so this block is permanent for that exact triple.

This mirrors the referenced Sense Finance finding: a permissionless "sponsor"/"create" action can pre-empt a PDA that a privileged/intended flow needs, permanently denying that flow the ability to ever execute for those parameters.

### Impact Explanation
This permanently denies the permission-gated pool-creation path (`initialize_with_permission`) for any specific `(amm_config, token_0_mint, token_1_mint)` combination that an attacker chooses to front-run. Since `PoolState` PDAs cannot be removed or recreated, the project intending to use the permissioned flow for that exact config/token pair is permanently blocked and must either use a different AMM config index or accept the attacker-created (unpermissioned, arbitrarily priced/seeded) pool instead — bypassing the entire purpose of the permission gate. This is a denial-of-service against a privileged capability of the protocol, causing loss of the intended controlled-launch mechanism.

### Likelihood Explanation
Likelihood is high: `amm_config` addresses are derived from a small, enumerable index space and are public; token mints intended for a permissioned launch are typically known or guessable ahead of time (e.g., the mint is created/announced before the pool). The `initialize` instruction is fully permissionless and requires no special access, so any actor watching for a specific token pair about to be paired under a given `amm_config` can race to call `initialize` first, paying only the pool-creation cost.

### Recommendation
Segregate the PDA seed spaces so that permission-gated pools cannot collide with permissionless pool PDAs — e.g., include a discriminator (such as a "permissioned" flag or a distinct seed prefix) in the `pool_state` PDA derivation for `initialize_with_permission`, so that a permissionless `initialize` call for the same `(amm_config, token_0_mint, token_1_mint)` cannot occupy the address that a permissioned pool would need.

### Proof of Concept
1. Determine the target `amm_config` PDA (deterministic from `AMM_CONFIG_SEED` + a known index) and the `token_0_mint`/`token_1_mint` that a permissioned project intends to use with `initialize_with_permission`.
2. Compute the resulting `pool_state` PDA using `[POOL_SEED, amm_config, token_0_mint, token_1_mint]` — identical derivation used by both instructions, as seen in [6](#0-5) .
3. As an unprivileged attacker (no `Permission` account required), call `initialize` with that `amm_config`, `token_0_mint`, `token_1_mint`, funding minimal `init_amount_0`/`init_amount_1`. This succeeds via `create_pool`, allocating and setting ownership of the `pool_state` PDA to the program.
4. The legitimate permissioned party later calls `initialize_with_permission` with the same `amm_config`/mints. `create_pool` now finds `pool_account_info.owner != &system_program::ID` and reverts with `ErrorCode::NotApproved`, permanently blocking that permissioned pool from ever being created at this deterministic address.

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-24)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L39-50)
```rust
    /// CHECK: Initialize an account to store the pool state
    /// PDA account:
    /// seeds = [
    ///     POOL_SEED.as_bytes(),
    ///     amm_config.key().as_ref(),
    ///     token_0_mint.key().as_ref(),
    ///     token_1_mint.key().as_ref(),
    /// ],
    ///
    /// Or random account: must be signed by cli
    #[account(mut)]
    pub pool_state: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L364-403)
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
```

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L42-53)
```rust
    /// CHECK: Initialize an account to store the pool state
    /// PDA account:
    /// seeds = [
    ///     POOL_SEED.as_bytes(),
    ///     amm_config.key().as_ref(),
    ///     token_0_mint.key().as_ref(),
    ///     token_1_mint.key().as_ref(),
    /// ],
    ///
    /// Or random account: must be signed by cli
    #[account(mut)]
    pub pool_state: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L153-216)
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

    /// Program to create mint account and mint tokens
    pub token_program: Program<'info, Token>,
    /// Spl token program or token program 2022
    pub token_0_program: Interface<'info, TokenInterface>,
    /// Spl token program or token program 2022
    pub token_1_program: Interface<'info, TokenInterface>,
    /// Program to create an ATA for receiving position NFT
    pub associated_token_program: Program<'info, AssociatedToken>,
    /// To create a new program account
    pub system_program: Program<'info, System>,
    // remaining account
    // #[account(
    //     seeds = [
    //     SUPPORT_MINT_SEED.as_bytes(),
    //     token_0_mint.key().as_ref(),
    // ],
    //     bump
    // )]
    // pub support_mint0_associated: Account<'info, SupportMintAssociated>,

    // #[account(
    //     seeds = [
    //     SUPPORT_MINT_SEED.as_bytes(),
    //     token_1_mint.key().as_ref(),
    // ],
    //     bump
    // )]
    // pub support_mint1_associated: Account<'info, SupportMintAssociated>,
}

pub fn initialize_with_permission(
    ctx: Context<InitializeWithPermission>,
    init_amount_0: u64,
    init_amount_1: u64,
    open_time: u64,
    creator_fee_on: CreatorFeeOn,
) -> Result<()> {
    let mint0_associated_is_initialized = support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_0_mint,
    )?;
    let mint1_associated_is_initialized = support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_1_mint,
    )?;
    if !(is_supported_mint(&ctx.accounts.token_0_mint, mint0_associated_is_initialized).unwrap()
        && is_supported_mint(&ctx.accounts.token_1_mint, mint1_associated_is_initialized).unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
    }

    if ctx.accounts.amm_config.disable_create_pool {
        return err!(ErrorCode::NotApproved);
    }
```

**File:** client/src/instructions/amm_instructions.rs (L46-59)
```rust
    let pool_account_key = if random_pool_id.is_some() {
        random_pool_id.unwrap()
    } else {
        Pubkey::find_program_address(
            &[
                POOL_SEED.as_bytes(),
                amm_config_key.to_bytes().as_ref(),
                token_0_mint.to_bytes().as_ref(),
                token_1_mint.to_bytes().as_ref(),
            ],
            &program.id(),
        )
        .0
    };
```

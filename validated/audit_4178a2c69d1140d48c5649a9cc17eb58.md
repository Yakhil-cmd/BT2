### Title
Permission-gated pool creation (`initialize_with_permission`) can be fully bypassed by calling the permissionless `initialize` instruction with the same `amm_config` - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` is designed to require an on-chain `Permission` PDA (created only by the program admin via `create_permission_pda`) before a payer may create a pool for a given `amm_config`. However, this authorization gate exists only inside `initialize_with_permission`'s account-validation constraints. The sibling instruction `initialize` performs the exact same privileged action (creating a pool bound to an arbitrary `AmmConfig`) and checks only `amm_config.disable_create_pool`, with no requirement for a `Permission` account at all. Because `AmmConfig` has no field that restricts a given config to "permissioned-only" pool creation, any unprivileged user can simply call `initialize` instead of `initialize_with_permission` to create a pool under any `amm_config` the admin intended to gate, completely bypassing the permission check.

### Finding Description
`InitializeWithPermission` derives the gating account from the payer's own key: [1](#0-0) 
This requires that a `Permission` account for `payer` was previously created by the admin-controlled `create_permission_pda` instruction: [2](#0-1) 

The instruction otherwise performs identical logic to the unrestricted `initialize` instruction — same `amm_config` type, same `disable_create_pool` check, same pool/vault/LP-mint creation flow: [3](#0-2) [4](#0-3) 

Crucially, `AmmConfig` carries no field indicating that a specific config is reserved for permissioned creation only — it only has a generic `disable_create_pool` flag shared by both code paths: [5](#0-4) 

Both `initialize` and `initialize_with_permission` are exposed as independent public entrypoints in `lib.rs`, and `initialize` never references `Permission` at all: [6](#0-5) 

This mirrors the CVE bug-class pattern: an authentication/authorization requirement ("client cert on tls-auth-port") is enforced on one access path but is entirely skipped when the *same privileged operation* is reached through an alternate, equally valid entrypoint ("regular tls-port/TCP port"). Here, the "regular port" equivalent is the plain `initialize` instruction.

### Impact Explanation
Any unpermissioned, unprivileged actor can create a pool bound to an `amm_config` that the admin intended to restrict to permissioned creators, entirely negating the purpose of the `Permission` PDA allowlist mechanism. This is an unauthorized privileged effect: the on-chain access-control primitive (`Permission` account gating) provides no actual enforcement because the privileged action (pool creation under a given config) is reachable without it via a parallel instruction.

### Likelihood Explanation
High likelihood/trivial exploitation: the attacker needs only to submit a standard `initialize` transaction with attacker-chosen accounts (including any existing `amm_config` the admin wanted permission-gated), no special accounts, signatures, or privileges beyond being a normal token holder are required.

### Recommendation
Add an explicit flag on `AmmConfig` (e.g., `require_permission_for_pool_creation`) and enforce it in both `initialize` and `initialize_with_permission` — rejecting `initialize` when the flag is set (forcing use of the permissioned path), or otherwise unify pool creation into a single instruction whose permission check cannot be bypassed by choosing an alternate entrypoint.

### Proof of Concept
1. Admin creates an `AmmConfig` intended to require permissioned pool creation and expects clients to only use `initialize_with_permission`.
2. Attacker (who has no `Permission` PDA created for them) submits a transaction calling `initialize` with `amm_config` set to that same config, along with attacker-controlled `token_0_mint`/`token_1_mint` and token accounts.
3. `initialize` succeeds because it never checks for a `Permission` account — see the account struct and handler body which reference only `disable_create_pool`, never `Permission`: [7](#0-6) 
4. The pool is created identically to what `initialize_with_permission` would have produced, fully bypassing the intended allowlist control.

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

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L193-221)
```rust
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
    let mut open_time = open_time;
    let block_timestamp = clock::Clock::get()?.unix_timestamp as u64;
    if open_time <= block_timestamp {
        open_time = block_timestamp + 1;
    }
```

**File:** programs/cp-swap/src/instructions/admin/create_permission_pda.rs (L14-20)
```rust
#[derive(Accounts)]
pub struct CreatePermissionPda<'info> {
    #[account(
        mut,
        constraint = (owner.key() == crate::admin::ID || owner.key() == crate::create_permission_pda_owner::ID) @ ErrorCode::InvalidOwner
    )]
    pub owner: Signer<'info>,
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

**File:** programs/cp-swap/src/instructions/initialize.rs (L182-208)
```rust
pub fn initialize(
    ctx: Context<Initialize>,
    init_amount_0: u64,
    init_amount_1: u64,
    mut open_time: u64,
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
    let block_timestamp = clock::Clock::get()?.unix_timestamp as u64;
    if open_time <= block_timestamp {
        open_time = block_timestamp + 1;
    }
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

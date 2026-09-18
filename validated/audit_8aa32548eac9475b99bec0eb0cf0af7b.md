### Title
`InitializeWithPermission` lets the permissioned payer assign an arbitrary, unrelated address as `pool_creator`, hijacking future creator-fee rights - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`create_permission_pda` gates permission by the `permission_authority` field, and `InitializeWithPermission` checks that a `Permission` PDA exists for the caller (`payer`) via the seeds `[PERMISSION_SEED, payer.key()]` [1](#0-0) , but the `creator` account that ends up being recorded as `pool_creator` is a completely unchecked, non-signing account [2](#0-1) . This mirrors the reported XO-constructor bug class: a privileged-setter path (`owner_`/`creator`) accepts a caller-controlled value with no constraint tying it to the entity that is supposed to hold that role, so the initializer can freely assign the sensitive role to any address, including itself.

### Finding Description
In `InitializeWithPermission`, permission to create a pool is verified only against `payer` — the PDA `permission` is derived from `payer.key()` [1](#0-0) , and it must exist (created earlier by an admin/`create_permission_pda_owner` via `create_permission_pda`, which binds the PDA to a specific `permission_authority`) [3](#0-2) .

However, the `creator` field of `InitializeWithPermission` — the account whose key becomes `pool_state.pool_creator` — is declared as:
```
/// CHECK: creator of pool
pub creator: UncheckedAccount<'info>,
``` [2](#0-1) 

There is no `address =`, `constraint =`, or signer requirement linking `creator` to `payer`, to `permission.authority`, or to any other verified identity. The value is taken as-is and passed straight into `pool_state.initialize(...)`:
```
pool_state.initialize(
    ctx.bumps.authority,
    liquidity,
    open_time,
    ctx.accounts.creator.key(),
    ...
``` [4](#0-3) 

This is exactly the class of bug in the report: a constructor/initializer accepts an attacker-supplied address for a privileged role field with only an incomplete/absent check, letting the caller (who only needed a `Permission` PDA keyed to `payer`, unrelated to `creator`) set `pool_creator` to any address they choose — including their own wallet, or, more importantly, an address other than the one the permission-authority (protocol admin) intended to authorize as pool creator.

`pool_creator` is a privileged role in this program: it is the sole signer authorized to call `collect_creator_fee` (`address = pool_state.load()?.pool_creator` constraint) [5](#0-4) , and it also determines who receives the permissionless variant's payout [6](#0-5) .

### Impact Explanation
Because `creator` is unchecked, the permission-holding `payer` can:
1. Set `pool_creator` to their own key even though the intent of the permissioned-creation model is to let the protocol admin control which entity is credited as the pool's official creator (separate from the transaction fee payer) — collapsing the separation of "who is authorized to create a permissioned pool" from "who receives creator fees forever."
2. More critically, set `pool_creator` to an address the `permission_authority`/admin never intended to receive fees at all, since nothing binds `creator` to `permission.authority`. This lets a single permission holder mint pools that permanently siphon accruing creator fees (`creator_fees_token_0`/`creator_fees_token_1`, funded by every subsequent swap through the pool) to an address of their choosing, with no way to correct it after `PoolState` is initialized. This is an unauthorized privileged effect (control over a fee stream) obtained purely by an unchecked account substitution during a single instruction.

### Likelihood Explanation
Any account that already holds a `Permission` PDA (an entity approved to call `initialize_with_permission`) can trigger this in a single transaction by simply passing an arbitrary pubkey for the `creator` account — no signature or extra approval is required for that account, since it is `UncheckedAccount`. This requires only attacker-chosen accounts/data in one instruction call, matching the required reachable-path criteria.

### Recommendation
Constrain `creator` in `InitializeWithPermission` so it cannot be freely chosen: either require `creator` to equal `ctx.accounts.permission.authority` (binding the initializer's granted permission to the creator identity actually approved by the admin), or require `creator` to be a `Signer` and additionally validate it against the `Permission` PDA/authority, similar to how `collect_creator_fee` binds `creator` to `pool_state.pool_creator` via an `address =` constraint.

### Proof of Concept
1. Admin calls `create_permission_pda` authorizing `permission_authority = A`, creating `Permission` PDA at `[PERMISSION_SEED, A]` [7](#0-6) .
2. Attacker, controlling wallet `A` as `payer`, calls `initialize_with_permission`, passing the correct `permission` PDA (derived from `payer.key() = A`) to satisfy the seeds check [1](#0-0) , but supplies `creator = B` — any arbitrary pubkey they control, unrelated to `A` or to any admin approval.
3. The instruction succeeds; `pool_state.pool_creator` is set to `B` [4](#0-3) .
4. From then on, only `B` (attacker-controlled) can call `collect_creator_fee` to drain all accrued `creator_fees_token_0`/`creator_fees_token_1` from every swap through this pool [5](#0-4) , with no mechanism to change `pool_creator` afterward.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L26-27)
```rust
    /// CHECK: creator of pool
    pub creator: UncheckedAccount<'info>,
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

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L357-372)
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
        creator_fee_on,
        true,
    );
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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L10-13)
```rust
pub struct CollectCreatorFee<'info> {
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L17-20)
```rust
    /// The pool creator that receives the collected creator fees
    /// CHECK: the address is constrained to the `pool_creator` recorded in `pool_state`
    #[account(address = pool_state.load()?.pool_creator)]
    pub creator: UncheckedAccount<'info>,
```

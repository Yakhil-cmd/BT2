## Answer

The Jenkins Nomad advisory describes a missing-permission-check pattern where a privileged action is exposed without verifying the caller has the correct authority. The closest analog in this program is a **permission-check/privilege-binding mismatch in `initialize_with_permission`**: the instruction verifies that `payer` owns a `Permission` PDA, but then assigns the privileged `pool_creator` role to a completely different, unchecked, non-signing account (`creator`), which is never validated by the permission check at all.

### Title
Permission check is bound to `payer` while the privileged `pool_creator` role is granted to an unverified `creator` account - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` gates pool creation behind a `Permission` PDA that is derived from and tied to `payer.key()`: [1](#0-0) . However, the privileged `pool_creator` field stored in `PoolState` — which later controls who receives creator fees — is set to `ctx.accounts.creator.key()`, a separate `UncheckedAccount` that is neither a signer nor constrained to match `payer` or the `permission.authority` field: [2](#0-1) [3](#0-2) .

### Finding Description
The `Permission` account only proves that whoever pays (`payer`) has been allow-listed by an admin via `create_permission_pda`, which enforces `permission.authority == payer` through the PDA seeds `[PERMISSION_SEED, permission_authority.key()]` matched against `[PERMISSION_SEED, payer.key()]`: [4](#0-3) . The check therefore authenticates `payer`, not `creator`.

Despite this, the function assigns the `pool_creator` field — the account that will forever be entitled to `collect_creator_fee` / `collect_creator_fee_permissionless` payouts for that pool — to `creator`, an `UncheckedAccount` with zero constraints: [2](#0-1) . Nothing ties `creator` to the permission-holder `payer`, nothing requires `creator` to sign, and nothing prevents `creator` from being set to an arbitrary attacker-controlled pubkey supplied in the same transaction.

Once set at pool initialization, `pool_creator` is immutable (no update instruction exists in the reviewed instruction set), and it is the sole authority checked by `collect_creator_fee` (`address = pool_state.load()?.pool_creator`) and the fee destination for `collect_creator_fee_permissionless`: [5](#0-4) [6](#0-5) .

This is analogous to CWE-862 (Missing Authorization): a permission check is performed, but it is checked against the wrong principal, so the actually-privileged effect (granting the permanent creator-fee-collection right) is applied to an unauthenticated, attacker-controlled account rather than the vetted `payer`/permission holder.

### Impact Explanation
Any account that has been granted a `Permission` PDA (i.e., is allow-listed by an admin to create a permissioned pool) can front an arbitrary attacker's `creator` pubkey into `pool_creator`. This diverts the entire ongoing creator-fee revenue stream of that pool to an unauthorized/unintended address chosen at pool-creation time, permanently (since the field cannot later be corrected). It can also be abused the opposite way — a permitted payer could unknowingly or maliciously assign `pool_creator` to someone with no legitimate claim, or an attacker who colludes with (or compromises) a permission holder's transaction construction could redirect fees to themselves. This is a concrete misappropriation of pool/LP-adjacent fee funds via an unauthorized privileged assignment, fitting the "unauthorized privileged effect" acceptance criterion.

### Likelihood Explanation
Exploitation requires only a single call to `initialize_with_permission` by any address that already holds a valid `Permission` PDA (an allow-listed pool creator), supplying an arbitrary `creator` account key in the instruction's account list — no signature or additional validation is required on `creator`. Given that `initialize_with_permission` is explicitly designed to be called by permission holders and `creator` is documented only as "creator of pool" with a `CHECK` comment and no runtime constraint, the missing binding is directly and trivially reachable.

### Recommendation
Constrain `creator` to be authenticated consistently with the permission check — e.g., require `creator` to equal `payer` (or explicitly require `creator` to be a `Signer` and change the `Permission` PDA seed to be derived from `creator.key()` instead of `payer.key()`, and validate `permission.authority == creator.key()` in the account constraints of `InitializeWithPermission`) before assigning it to `pool_state.pool_creator`.

### Proof of Concept
1. Address `P` obtains a `Permission` PDA via `create_permission_pda` with `permission_authority = P`, making `permission = PDA[PERMISSION_SEED, P]` (`programs/cp-swap/src/instructions/admin/create_permission_pda.rs`).
2. `P` calls `initialize_with_permission` as `payer`, passing `permission = PDA[PERMISSION_SEED, P]` (satisfies the seeds constraint) but passing an arbitrary attacker-controlled pubkey `A` (not a signer, no relation to `P`) as the `creator` account.
3. The instruction succeeds; `pool_state.initialize(..., ctx.accounts.creator.key(), ...)` sets `pool_creator = A` (`programs/cp-swap/src/instructions/initialize_with_permission.rs:357-372`).
4. `A` can now call `collect_creator_fee_permissionless` (or `collect_creator_fee` after becoming the creator-fee address of record) and permanently receive all accrued creator fees for that pool, despite never having been vetted by the `Permission` system that was supposed to gate pool creation.

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

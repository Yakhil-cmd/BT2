### Title
`initialize_with_permission` permission check is bound to `payer`, not `creator`, letting a verified payer act as a proxy for unverified creators - (File: programs/cp-swap/src/instructions/initialize_with_permission.rs)

### Summary
`initialize_with_permission` gates pool creation with a `Permission` PDA derived from the `payer` account, but the `creator` account that is actually recorded as `pool_creator` (and later receives creator-fee revenue) is a completely unconstrained `UncheckedAccount`. Any address holding a valid `Permission` PDA can therefore repeatedly call this instruction on behalf of arbitrary, un-vetted third-party `creator` addresses, turning the "verified" payer into a permissionless proxy — the same bug class described in the external report, where an attested/verified account is used to launder access for unverified actors.

### Finding Description
The instruction's account validation only checks that a `Permission` PDA exists for `payer`: [1](#0-0) 

The `creator` field, by contrast, carries no constraint at all tying it to `payer` or to the `permission` account's `authority` field: [2](#0-1) 

`Permission` PDAs are only created by a hard-coded admin/owner for a specific `permission_authority` pubkey, and the account layout doesn't encode any restriction on who can be named `creator` downstream: [3](#0-2) 

At the end of `initialize_with_permission`, the pool's `pool_creator` field is set from the unchecked `creator` account, not from `payer`: [4](#0-3) 

That `pool_creator` field is later used, without any additional verification step, to authorize collection of accumulated creator fees to any address the pool records as creator: [5](#0-4) 

Because the only KYC/verification-equivalent gate in this flow (the `Permission` PDA) is checked against `payer` and never propagated to `creator`, the verified `payer` can invoke `initialize_with_permission` in a single, permissionless transaction naming any third-party pubkey as `creator`. This is functionally identical to the reported issue: a verified/attested identity acts as a pass-through that lets unverified parties obtain the privileges (here, "verified pool creator" status and future creator-fee income) that the permission system was meant to restrict to vetted accounts.

### Impact Explanation
Impact is Medium/High: the permissioned pool-creation feature exists specifically to restrict who can create "verified" pools and earn creator fees from them (analogous to Coinbase's verified-pools attestation model). Because `creator` is decoupled from the permission check, a single verified account can act as an unlimited proxy, minting "verified creator" status and future fee streams for arbitrary unverified/sanctioned entities. This defeats the entire purpose of the permission gate and lets non-vetted actors accumulate protocol-sanctioned creator fee revenue via `collect_creator_fee` / `collect_creator_fee_permissionless` without ever holding a `Permission` PDA themselves.

### Likelihood Explanation
Likelihood is Medium: it requires only one verified account (obtained legitimately or through a compromised/malicious verified party) and a single call to `initialize_with_permission` with an attacker-chosen `creator` argument — no special capital, no upgrade, no additional privileged step. This is strictly easier to execute than the original off-chain report scenario, since it needs no upgradeable-proxy trick — the vulnerability is present in the instruction's account constraints as written.

### Recommendation
Add an explicit constraint tying `creator` to the verified identity, e.g. require `creator.key() == payer.key()` or `creator.key() == permission.authority`, so that the entity that passed the permission check is the same entity recorded as `pool_creator` and eligible for creator fees. Alternatively, derive/validate the `permission` PDA using `creator` instead of (or in addition to) `payer`.

### Proof of Concept
1. Admin/owner calls `create_permission_pda` to grant `permission_authority = V` (a verified/KYC'd pubkey) a `Permission` PDA, per `programs/cp-swap/src/instructions/admin/create_permission_pda.rs`.
2. Attacker `A` (unverified) convinces or colludes with `V` (or `V`'s signing key/service) to sign a single `initialize_with_permission` transaction where:
   - `payer = V` (satisfies the `Permission` PDA seed check),
   - `creator = A` (no constraint prevents this).
3. `pool_state.initialize(...)` records `pool_creator = A`, per lines 357-372 of `initialize_with_permission.rs`.
4. `A` subsequently calls `collect_creator_fee_permissionless` (or `collect_creator_fee`) and receives all accumulated creator fees for the pool, despite never holding a `Permission` PDA or undergoing verification, per `programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs` lines 17-20.
5. This can be repeated for arbitrarily many distinct `creator` addresses using the same verified `payer`, turning `V` into a permissionless proxy for granting "verified pool creator" status to unverified third parties.

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L17-20)
```rust
    /// The pool creator that receives the collected creator fees
    /// CHECK: the address is constrained to the `pool_creator` recorded in `pool_state`
    #[account(address = pool_state.load()?.pool_creator)]
    pub creator: UncheckedAccount<'info>,
```

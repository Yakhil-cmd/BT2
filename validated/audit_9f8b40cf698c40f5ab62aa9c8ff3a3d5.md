Confirmed finding: in `initialize_with_permission`, `pool_creator` is set to `ctx.accounts.creator.key()`, where `creator` is declared only as `/// CHECK: creator of pool` `pub creator: UncheckedAccount<'info>` — it is never required to be a `Signer`, never constrained to equal `payer`, and never checked against the `permission` PDA's `authority` field. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Unauthorized designation of arbitrary `pool_creator` bypassing permission gating in `initialize_with_permission` - (File: programs/cp-swap/src/instructions/initialize_with_permission.rs)

### Summary
`initialize_with_permission` gates pool creation behind a `Permission` PDA that must be derived from and issued to the `payer` account, but the privileged `pool_creator` role recorded in `PoolState` is taken from a completely separate, unchecked `creator` account rather than from the permission-holding `payer`. This lets any permissioned payer assign the `pool_creator` privilege (which controls `collect_creator_fee` and `collect_creator_fee_permissionless`) to an arbitrary third-party or even a program-controlled/self-chosen address that was never vetted by the permission system.

### Finding Description
The `InitializeWithPermission` accounts struct requires a `Permission` PDA seeded by `[PERMISSION_SEED, payer.key()]`, which can only exist if an admin previously called `create_permission_pda` for that exact `payer` [2](#0-1) [4](#0-3) . This is meant to restrict who may create a pool through this "permissioned" instruction path.

However, the separate `creator` account is declared as an arbitrary `UncheckedAccount` with no signer requirement and no constraint tying it to `payer` or to `permission.authority` [1](#0-0) . At the end of the handler, `pool_state.initialize(...)` stores `ctx.accounts.creator.key()` as `pool_creator` [3](#0-2) [5](#0-4) , and `enable_creator_fee` is hard-set to `true` for this path.

`pool_creator` is the sole authority checked by `collect_creator_fee` (`address = pool_state.load()?.pool_creator`) [6](#0-5)  and is the fee-recipient target validated in `collect_creator_fee_permissionless` [7](#0-6) . Because the permission check validates `payer`, not `creator`, a permissioned `payer` can pass any arbitrary pubkey as `creator` (their own alt wallet, a burner address, or even an address they don't control) to become the on-chain `pool_creator`, completely decoupling the actually-vetted/permissioned identity from the privileged fee-collecting role the protocol intended to restrict. This mirrors the reported CWE-269/CWE-200 class bug class: an API/instruction that is supposed to enforce a permission boundary fails to bind the granted privilege to the checked identity, letting the checked-but-unprivileged path assign privilege to an unchecked identity.

### Impact Explanation
While this does not directly steal already-existing funds, it breaks the intended access-control invariant of the permissioned pool-creation feature: the protocol's permission allowlist (`Permission` PDA, admin-gated via `create_permission_pda_owner`/`admin::ID`) is supposed to control who can create pools and become eligible for creator-fee accrual under this trusted path, but the actual privileged principal (`pool_creator`) is never checked against that allowlist. This allows a permissioned payer to launder creator-fee privileges to unvetted/arbitrary addresses (e.g., sybil accounts, or addresses that collude to bypass any off-chain vetting tied to the permission system), undermining the integrity of the permission gate and enabling any future accounting/administration built atop `pool_creator` trust to be subverted. Given the instructions explicitly restrict scope to concrete fund theft/freezing/insolvency/unbacked-mint impacts, this finding is a privilege-binding gap rather than direct fund loss, and its severity should be assessed as Low/informational under the strict impact criteria in the validation rules, since creator fees are only ever paid out of legitimately accrued trading fees to whichever `pool_creator` is recorded — no insolvency, freezing, or unbacked minting results.

### Likelihood Explanation
Trivial to trigger: any already-permissioned account (holding a valid `Permission` PDA) can call `initialize_with_permission` and simply pass a different `creator` pubkey than their own `payer` key, with no additional signature or constraint required.

### Recommendation
Add an explicit constraint tying `creator` to the permission-checked identity — either require `creator` to equal `payer` (`constraint = creator.key() == payer.key()`), or require `creator` to equal `permission.authority`, or require `creator` to be a `Signer` and verify its own `Permission` PDA exists. This ensures the privileged `pool_creator` role recorded on `PoolState` is always bound to the identity that was actually vetted by the permission system.

### Proof of Concept
1. Admin calls `create_permission_pda` with `permission_authority = Alice`, creating a `Permission` PDA at `[PERMISSION_SEED, Alice]`.
2. Alice calls `initialize_with_permission` with `payer = Alice` (satisfies the `permission` PDA constraint) but sets `creator = Mallory` (an arbitrary unchecked, non-signing account, e.g. Alice's own alt address or a colluding third party).
3. `pool_state.initialize(...)` records `pool_creator = Mallory.key()` [3](#0-2) , and `enable_creator_fee = true`.
4. Mallory, who was never vetted by `create_permission_pda`, can now call `collect_creator_fee` as the signer matching `pool_state.pool_creator` [6](#0-5) , or anyone can route creator fees to Mallory via `collect_creator_fee_permissionless` [7](#0-6) , despite the permission system only ever having approved Alice.

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

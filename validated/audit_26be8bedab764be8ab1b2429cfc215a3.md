## Analysis: Missing zero-address validation on the `creator` account in `initialize_with_permission`

This is a valid analog to the reported `setNFT` missing zero-address check. In the Solidity report, an owner-controlled setter accepts an unchecked address that later gets relied upon for critical operations. In this Solana program, `InitializeWithPermission` accepts an arbitrary, unchecked `creator` account that is permanently recorded as `pool_creator` in `PoolState`, with no restriction against it being the zero/default `Pubkey`.

### Title
Missing zero-address check on `creator` in `initialize_with_permission` permanently locks creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`InitializeWithPermission::creator` is declared as an `UncheckedAccount<'info>` with only a `/// CHECK: creator of pool` comment and no constraint validating that it is non-zero or otherwise sane. Its value is written verbatim into `PoolState.pool_creator` via `PoolState::initialize`, and this field permanently gates both creator-fee-collection code paths.

### Finding Description
`InitializeWithPermission` accepts `creator` as a plain `UncheckedAccount` supplied by the caller, with no address validation: [1](#0-0) 

This value is passed straight into `pool_state.initialize(...)` as `pool_creator`, which stores it unconditionally: [2](#0-1) [3](#0-2) 

Unlike `update_config.rs`, which explicitly guards owner-address updates with `require_keys_neq!(new_owner, Pubkey::default())`, no equivalent check exists for `pool_creator` at pool creation time: [4](#0-3) 

`pool_creator` is later relied upon by both creator-fee-collection instructions. `collect_creator_fee` requires the `creator` account to be a `Signer` whose address matches `pool_state.pool_creator`: [5](#0-4) 

`collect_creator_fee_permissionless` allows any payer to trigger collection, but still derives the destination ATA's authority from the recorded `pool_creator`: [6](#0-5) [7](#0-6) 

If `creator` is set to `Pubkey::default()` at pool creation, `pool_creator` becomes the system-program/default address, which has no corresponding private key. `collect_creator_fee` then becomes permanently unreachable because no one can produce a valid signer for the default address, and `collect_creator_fee_permissionless` will still succeed in transferring accrued creator fees into an ATA owned by the unspendable default address.

### Impact Explanation
Any unprivileged pool creator invoking `initialize_with_permission` (creator-fee-enabled pool creation reachable without special privileges beyond being a normal pool creator) can set `creator = Pubkey::default()`. All creator fees subsequently accrued on that pool (`creator_fees_token_0`/`creator_fees_token_1`, per swap fee-split logic) become permanently locked: `collect_creator_fee` can never be signed for, and `collect_creator_fee_permissionless` sweeps the funds into an ATA nobody can control. This is a permanent freezing of LP/creator funds tied to a specific pool.

### Likelihood Explanation
Likelihood is high for any pool created via `initialize_with_permission` where the caller (deliberately or by mistake, since no client-side or on-chain validation exists) supplies `Pubkey::default()` (or any other unspendable/burn address) as `creator`. No elevated privileges are required — this is the standard, permissionless pool-creation flow used by ordinary swappers/pool creators.

### Recommendation
Add an explicit check in `InitializeWithPermission`'s account validation (or in `initialize_with_permission`) rejecting `creator.key() == Pubkey::default()`, mirroring the `require_keys_neq!(new_owner, Pubkey::default())` pattern already used in `update_config.rs`.

### Proof of Concept
1. Call `initialize_with_permission` with `creator` set to `Pubkey::default()` (system program ID / all-zero pubkey) along with valid mint/vault/config accounts.
2. `PoolState.pool_creator` is stored as `Pubkey::default()`.
3. Perform swaps on the pool so that `creator_fees_token_0`/`creator_fees_token_1` accrue.
4. Attempt `collect_creator_fee` — it can never be called because no signer exists for the default address.
5. Call `collect_creator_fee_permissionless` — it succeeds, creating an ATA whose authority is `Pubkey::default()` and transferring the accrued creator fees there, permanently locking them since no one holds the private key for that address.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L26-27)
```rust
    /// CHECK: creator of pool
    pub creator: UncheckedAccount<'info>,
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

**File:** programs/cp-swap/src/states/pool.rs (L150-152)
```rust
    ) {
        self.amm_config = amm_config.key();
        self.pool_creator = pool_creator.key();
```

**File:** programs/cp-swap/src/instructions/admin/update_config.rs (L63-73)
```rust
fn set_new_protocol_owner(amm_config: &mut Account<AmmConfig>, new_owner: Pubkey) -> Result<()> {
    require_keys_neq!(new_owner, Pubkey::default());
    #[cfg(feature = "enable-log")]
    msg!(
        "amm_config, old_protocol_owner:{}, new_owner:{}",
        amm_config.protocol_owner.to_string(),
        new_owner.key().to_string()
    );
    amm_config.protocol_owner = new_owner;
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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L61-79)
```rust
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

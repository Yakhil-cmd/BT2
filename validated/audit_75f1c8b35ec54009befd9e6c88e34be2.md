## Title
Missing zero-address validation on `creator` in `initialize_with_permission` permanently freezes accrued creator fees - (File: programs/cp-swap/src/instructions/initialize_with_permission.rs)

### Summary
`InitializeWithPermission` accepts `creator` as an unchecked, unvalidated account and stores it directly into `pool_state.pool_creator` with no check against `Pubkey::default()` (the zero/System-Program address). This mirrors the reported Factory bug class: an unvalidated privileged/beneficiary address parameter that, once persisted, can never be corrected and breaks a core downstream permission flow.

### Finding Description
In `initialize_with_permission.rs`, `creator` is declared as `UncheckedAccount<'info>` with only a doc comment ("CHECK: creator of pool") and no `constraint`/`require_keys_neq` validation: [1](#0-0) 

Whatever key is supplied is written verbatim into `pool_state.pool_creator` via `pool_state.initialize(...)`: [2](#0-1) 

That field is later relied upon as the sole authorization/beneficiary check in `collect_creator_fee`, which requires a `Signer` whose address equals `pool_state.pool_creator`: [3](#0-2) 

and in `collect_creator_fee_permissionless`, which builds associated token accounts owned by that same `pool_creator` address: [4](#0-3) [5](#0-4) 

If `creator` is set to `Pubkey::default()` (the all-zero System Program address, which has no corresponding private key), then:
1. `collect_creator_fee` can never be called, because no signer can ever produce a valid signature for that address.
2. `collect_creator_fee_permissionless` will still succeed in transferring accumulated `creator_fees_token_0/1` out of the pool vaults into ATAs whose `authority` is the zero address — tokens that are then permanently unrecoverable, since no keypair controls that authority.

This is directly analogous to the reported Factory issue: an address parameter accepted without a zero-address check becomes a persistent, unfixable state that disables a privileged/beneficiary operation, except here the consequence is concrete fund loss rather than just an inconvenience.

Compare this to the mitigations that already exist elsewhere in the codebase for the *same bug class* — `set_new_protocol_owner` and `set_new_fund_owner` in `update_config.rs` explicitly guard against the zero address: [6](#0-5) [7](#0-6) 

`initialize_with_permission`'s `creator` field has no equivalent check, which is the gap.

### Impact Explanation
Impact is Medium: it results in permanent freezing of creator-fee funds (via `collect_creator_fee_permissionless` pushing tokens to an unclaimable ATA) and permanent denial-of-service of the `collect_creator_fee` (self-service) path for that pool once `pool_creator` is the zero address. Unlike the referenced Factory report (pure availability/redeploy issue), this analog also causes real, permanent loss of already-accrued creator fees for that pool.

### Likelihood Explanation
`initialize_with_permission` is gated by a `Permission` PDA (`payer` must hold permission), so the caller creating the pool is not a fully anonymous/unprivileged actor, but the `creator` field itself is a separate, attacker-controlled account with zero validation — it can be set to the zero address either by mistake or intentionally by any permissioned pool creator. Once set, the flaw is unrecoverable since `pool_creator` is written once at `initialize` time with no update instruction.

### Recommendation
Add an explicit check in `InitializeWithPermission`'s account constraints or at the start of `initialize_with_permission` to reject `creator.key() == Pubkey::default()`, e.g.:
```rust
require_keys_neq!(ctx.accounts.creator.key(), Pubkey::default(), ErrorCode::InvalidCreator);
```
placed before `pool_state.initialize(...)` is called in `programs/cp-swap/src/instructions/initialize_with_permission.rs`.

### Proof of Concept
1. A permissioned account (holding a valid `Permission` PDA) calls `initialize_with_permission`, supplying `creator = Pubkey::default()` (the System Program / zero address) instead of a real keypair.
2. `pool_state.initialize(...)` persists `pool_creator = Pubkey::default()` with no validation, as shown in `programs/cp-swap/src/instructions/initialize_with_permission.rs:357-372`.
3. Swaps accrue `creator_fees_token_0`/`creator_fees_token_1` in `pool_state` over time.
4. Anyone calls `collect_creator_fee_permissionless`; the `#[account(address = pool_state.load()?.pool_creator)]` constraint on `creator` passes trivially since it just matches the stored zero address, and `creator_token_0`/`creator_token_1` ATAs are created with `associated_token::authority = creator` (the zero address) and receive the fee transfer.
5. These tokens are now held in accounts owned by the zero-address authority, which corresponds to no controllable keypair — the funds are permanently frozen. Separately, `collect_creator_fee` (the signer-gated variant) can never be invoked for this pool because no one can sign as `Pubkey::default()`.

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

**File:** programs/cp-swap/src/instructions/admin/update_config.rs (L75-85)
```rust
fn set_new_fund_owner(amm_config: &mut Account<AmmConfig>, new_fund_owner: Pubkey) -> Result<()> {
    require_keys_neq!(new_fund_owner, Pubkey::default());
    #[cfg(feature = "enable-log")]
    msg!(
        "amm_config, old_fund_owner:{}, new_fund_owner:{}",
        amm_config.fund_owner.to_string(),
        new_fund_owner.key().to_string()
    );
    amm_config.fund_owner = new_fund_owner;
    Ok(())
}
```

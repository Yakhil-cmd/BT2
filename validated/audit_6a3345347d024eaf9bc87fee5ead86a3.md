## Finding

### Title
Unvalidated `creator` account in `initialize_with_permission` permanently freezes creator fees at an uncontrollable address - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` stores an arbitrary, attacker-supplied `creator` account as the pool's `pool_creator` without any validation that it is a real, controllable address. Because the pool's `creator_fee_rate` (inherited from `AmmConfig`) is applied on every swap regardless of who `pool_creator` is, an unvalidated/zero-like `pool_creator` causes all accrued creator fees to become permanently unrecoverable — the same root cause as the reported `escrowPortion`/`escrowPool` coupling bug: a non-zero fee parameter paired with an unusable destination.

### Finding Description
In `InitializeWithPermission`, the `creator` account is declared as a plain `UncheckedAccount` with no signer requirement and no constraint preventing it from being `Pubkey::default()` or any other address nobody holds the private key for: [1](#0-0) 

This account is then written directly into `pool_state.pool_creator` at pool creation, with no zero-address or ownability check: [2](#0-1) 

Contrast this with the standard `Initialize` instruction, where `creator` is required to be a `Signer`, which inherently prevents this class of misconfiguration: [3](#0-2) 

Every swap accrues creator fees into `pool_state.creator_fees_token_0`/`creator_fees_token_1` according to `AmmConfig.creator_fee_rate`, independent of whether `pool_creator` is a valid, reachable address: [4](#0-3) 

Both collection paths are permanently gated on this same unvalidated `pool_creator` value: `collect_creator_fee` requires a signer matching `pool_creator`, and `collect_creator_fee_permissionless` sends the tokens to an ATA whose authority is `pool_creator`: [5](#0-4) [6](#0-5) 

If `creator` is set to `Pubkey::default()` (or any address with no corresponding keypair), no transaction can ever sign as `pool_creator`, and the permissionless variant will simply deposit fees into an ATA owned by an address nobody controls. Since `AmmConfig.creator_fee_rate` is a protocol-level parameter that can already be non-zero (set via `create_amm_config`/`update_amm_config`), any pool created through `initialize_with_permission` with a bad `creator` value locks 100% of that pool's creator-fee share forever.

### Impact Explanation
Every swap against such a pool permanently diverts a fraction of trade fees (`creator_fee_rate`) into `creator_fees_token_0`/`creator_fees_token_1`, which can never be withdrawn because no valid signer/owner exists for `pool_creator`. This is a permanent freezing of LP/trader-derived value inside the pool's vaults with no recovery path, analogous to the referenced report's loss of escrowed rewards.

### Likelihood Explanation
The `creator` field is supplied by whoever invokes `initialize_with_permission` (constrained only by holding a `Permission` PDA, not by any check on the `creator` value itself). A misconfigured client, integrator, or a payer intentionally passing `Pubkey::default()`/an arbitrary burn address will trigger this on every pool created that way, with fee accrual starting immediately from the first swap.

### Recommendation
Require `pool_creator` to be non-default (and ideally that the account is a valid signer-capable key) in `InitializeWithPermission`, e.g. add `require_keys_neq!(ctx.accounts.creator.key(), Pubkey::default())` before calling `pool_state.initialize`, mirroring the implicit guarantee that `Initialize::creator` already provides by being a `Signer`.

### Proof of Concept
1. Admin creates a `Permission` PDA for `payer` via `create_permission_pda`.
2. `payer` calls `initialize_with_permission`, passing `creator = Pubkey::default()` (or any address with no private key) as the `creator` account, and any `AmmConfig` with `creator_fee_rate > 0`.
3. `pool_state.pool_creator` is set to `Pubkey::default()` at [2](#0-1) .
4. On every subsequent swap, `creator_fee` is computed and credited to `pool_state.creator_fees_token_0/1` per [4](#0-3) .
5. `collect_creator_fee` cannot be called (no signer exists for `Pubkey::default()`), and `collect_creator_fee_permissionless` would deposit into an ATA owned by `Pubkey::default()`, from which funds can never be moved — permanently freezing the accrued creator fees.

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L22-24)
```rust
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/curve/calculator.rs (L126-131)
```rust
        let output_amount = if is_creator_fee_on_input {
            output_amount_swapped
        } else {
            creator_fee = Fees::creator_fee(output_amount_swapped, creator_fee_rate)?;
            output_amount_swapped.checked_sub(creator_fee)?
        };
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

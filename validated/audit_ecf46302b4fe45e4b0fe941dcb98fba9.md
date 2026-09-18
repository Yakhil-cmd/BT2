### Title
Missing validation that `creator` is non-default in `InitializeWithPermission` permanently locks creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`InitializeWithPermission` accepts an arbitrary, unconstrained `creator` account and stores it directly as `pool_creator` in `PoolState` without any check that it is non-zero/non-default, mirroring the reported Timelock issue where a missing zero-address check on a privileged role (`admin`) permanently breaks all functions gated on that role.

### Finding Description
In `InitializeWithPermission`, the `creator` field is declared as a bare, unchecked account with no signer requirement and no address constraint: [1](#0-0) 

Only the `payer` is required to hold a valid `Permission` PDA; the `creator` value is fully attacker/caller-controlled and copied verbatim into `PoolState.pool_creator` at pool creation: [2](#0-1) 

No check exists anywhere in the accounts struct or handler ensuring `creator.key() != Pubkey::default()` (or any other unusable/burn address). This differs from `Initialize` (non-permissioned path), where `creator` is a `Signer<'info>` and can therefore never be the zero/default address: [3](#0-2) 

Once `pool_creator` is set to `Pubkey::default()`, every function gated on that role becomes permanently unusable:
- `CollectCreatorFee` requires `creator` to be a **signer** matching `pool_state.pool_creator`, which is impossible for the default/system-program address since no private key exists for it: [4](#0-3) 
- The only remaining path, `CollectCreatorFeePermissionless`, still forces the accumulated fees to be transferred into an ATA whose authority is the unusable default `creator` account, meaning the tokens end up in a token account nobody can ever control or move: [5](#0-4) [6](#0-5) 

Creator fees continue to accrue on every swap into `pool_state.creator_fees_token_0/1`, which are physically backed by tokens withdrawn from the pool's trade flow, exactly as in `swap_base_input`/`swap_base_output`.

### Impact Explanation
Any pool created via `initialize_with_permission` with `creator` set to `Pubkey::default()` (accidentally by tooling/UI bugs, or intentionally) results in permanent, unrecoverable loss of all accrued creator fees for that pool's lifetime: the signer-gated collection path can never succeed (no private key for the default pubkey), and the permissionless path only relocates the funds into a token account with an equally unusable authority. This is a permanent freezing of funds analogous to the reported Timelock admin issue, where losing the ability to authenticate a stored role address bricks all functionality gated on it.

### Likelihood Explanation
The `creator` account is entirely unconstrained (not even required to be a signer), so triggering this only requires the permissioned `payer` to submit `initialize_with_permission` with `creator` set to the default/system pubkey — a single transaction with attacker/caller-chosen account inputs. No collusion with the admin/config owner is required, and it can happen from operator/tooling error just as easily as intentionally.

### Recommendation
Add an explicit non-default check on `creator` in `InitializeWithPermission`, mirroring the pattern already used for `protocol_owner`/`fund_owner` in `update_config.rs`:

```rust
require_keys_neq!(creator.key(), Pubkey::default(), ErrorCode::InvalidCreator);
``` [7](#0-6) 

placed either as an `#[account(constraint = ...)]` on the `creator` field or as an early check in `initialize_with_permission` before `pool_state.initialize(...)` is called.

### Proof of Concept
1. A caller holding a valid `Permission` PDA for their `payer` pubkey calls `initialize_with_permission`, passing `creator = 11111111111111111111111111111111` (System Program ID / `Pubkey::default()`).
2. The instruction succeeds; `pool_state.pool_creator` is set to the default pubkey via `pool_state.initialize(..., ctx.accounts.creator.key(), ...)`.
3. Swaps against the pool accrue `creator_fees_token_0`/`creator_fees_token_1` in `PoolState` as usual.
4. `collect_creator_fee` can never be called because no signer exists for the default pubkey (`address = pool_state.load()?.pool_creator` constraint can never be satisfied by a real signer).
5. `collect_creator_fee_permissionless` can be called by anyone, but it creates ATAs with `associated_token::authority = creator` (the default pubkey) and transfers the fees there — funds are now held in accounts with an authority no one can ever sign for, permanently locking them.

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-24)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
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

**File:** programs/cp-swap/src/instructions/admin/update_config.rs (L63-65)
```rust
fn set_new_protocol_owner(amm_config: &mut Account<AmmConfig>, new_owner: Pubkey) -> Result<()> {
    require_keys_neq!(new_owner, Pubkey::default());
    #[cfg(feature = "enable-log")]
```

### Title
Missing zero-address / arbitrary-account validation on `creator` in `initialize_with_permission` permanently freezes accrued creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` accepts `creator` as a completely unconstrained `UncheckedAccount`, and stores it directly into `PoolState.pool_creator` without any check that it is non-default, controllable, or even related to the transaction's signer. This mirrors the reported `DSAuth.setOwner` bug class: an owner/authority-like field is set from user-supplied input with no zero-address (or "meaningful address") verification.

### Finding Description
In `InitializeWithPermission`, the `creator` account is declared with no constraints at all: [1](#0-0) 

It is later persisted verbatim into the pool state via `pool_state.initialize(...)`: [2](#0-1) 

`PoolState.pool_creator` is the field that determines who is authorized to collect creator fees: [3](#0-2) 

`collect_creator_fee` requires the `creator` signer to match `pool_state.pool_creator` exactly: [4](#0-3) 

However, `collect_creator_fee_permissionless` lets *anyone* trigger fee collection, transferring accrued creator fees into an associated token account whose authority is whatever `pool_creator` was recorded — again with no validation that this address is non-default or otherwise meaningful: [5](#0-4) [6](#0-5) 

By contrast, `initialize` (the non-permissioned path) forces `creator` to be a `Signer`, which structurally prevents it from ever being the system-program/default address: [7](#0-6) 

`initialize_with_permission` breaks that invariant by decoupling the pool-creator identity from the transaction signer (`payer`), and never checks `creator.key() != Pubkey::default()` (or any other sanity constraint), exactly analogous to the missing zero-address check in `DSAuth.setOwner`.

### Impact Explanation
If `creator` is submitted as `Pubkey::default()` (the System Program ID, which cannot sign any future transaction), the pool is created successfully and begins accruing `creator_fees_token_0`/`creator_fees_token_1`. Because no private key exists for the default pubkey, `collect_creator_fee` (which requires the `creator` to be a `Signer` matching `pool_state.pool_creator`) can never succeed. Meanwhile, `collect_creator_fee_permissionless` can still be called by anyone, which will `init_if_needed` an associated token account owned by `Pubkey::default()` and irrevocably transfer the accumulated creator fees into it — funds that are then permanently unreachable/frozen, since no one holds the signing authority for the zero address. This is a permanent freezing of protocol/creator fee funds, matching the accepted impact class (permanent freezing of fee-ledger funds).

### Likelihood Explanation
Any account holding a valid `Permission` PDA (an approved/permissioned payer) can call `initialize_with_permission` and set `creator` to an arbitrary address of their choosing, including the default `Pubkey`, in a single transaction with attacker-chosen accounts — no additional privilege or race condition is required. The likelihood of a permissioned party doing this by mistake (e.g., a client bug omitting the creator address, defaulting it to `Pubkey::default()`) or maliciously self-sabotaging future fee distribution to an unreachable account is realistic given no on-chain guard exists.

### Recommendation
Add an explicit constraint on the `creator` account in `InitializeWithPermission`, e.g. `constraint = creator.key() != Pubkey::default() @ ErrorCode::InvalidInput`, and consider additionally requiring `creator` to be a recognized/permissioned or signer-verifiable identity (mirroring how `set_new_protocol_owner`/`set_new_fund_owner` already use `require_keys_neq!(new_owner, Pubkey::default())` for the AMM config owners): [8](#0-7) 

### Proof of Concept
1. Attacker/permissioned payer obtains a valid `Permission` PDA for their `payer` key (via `create_permission_pda`, gated by the protocol admin's allow-list).
2. Calls `initialize_with_permission` with `creator = Pubkey::default()` (System Program ID) and normal `token_0_mint`/`token_1_mint`/liquidity amounts.
3. Pool is created; `pool_state.pool_creator == Pubkey::default()`.
4. Swaps occur against the pool, accruing `creator_fees_token_0`/`creator_fees_token_1` in `pool_state`.
5. Anyone calls `collect_creator_fee_permissionless`, passing `creator = Pubkey::default()` (matches the `address = pool_state.load()?.pool_creator` constraint) and creating ATAs owned by `Pubkey::default()` for `vault_0_mint`/`vault_1_mint`.
6. Creator fees are transferred into those ATAs; because `Pubkey::default()` has no private key, the tokens are permanently unrecoverable — `collect_creator_fee` (the only other feasible way to move fee-owner funds) can never be satisfied since the required `Signer` can never sign for the default key.

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

**File:** programs/cp-swap/src/states/pool.rs (L66-70)
```rust
pub struct PoolState {
    /// Which config the pool belongs
    pub amm_config: Pubkey,
    /// pool creator
    pub pool_creator: Pubkey,
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

**File:** programs/cp-swap/src/instructions/initialize.rs (L21-24)
```rust
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
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

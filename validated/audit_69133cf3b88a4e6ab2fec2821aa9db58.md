### Title
Pool creator can be set to the zero address in `initialize_with_permission`, permanently locking creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`InitializeWithPermission::creator` is declared as an `UncheckedAccount` with no signer requirement and no constraint forbidding `Pubkey::default()`. The value supplied for this account is stored directly as `pool_state.pool_creator` with no validation, mirroring the `BvbProtocol.transferPosition` bug class where a position/ownership field can be set to `address(0)` because the recipient is never validated.

### Finding Description
In the accounts struct, `creator` has only a `CHECK:` comment and no `address`, `constraint`, or `Signer` requirement: [1](#0-0) 

Any account permissioned to call the instruction (via the `permission` PDA keyed on `payer`) can pass an arbitrary `creator` account, including the system-program/all-zero `Pubkey::default()`. This value is then stored unchecked into `pool_state.pool_creator`: [2](#0-1) 

`PoolState::initialize` writes the value straight into the `pool_creator` field with no zero-address guard: [3](#0-2) 

`enable_creator_fee` is hard-coded to `true` for this instruction path, so the pool will accrue creator fees (`creator_fees_token_0/1`) from swap activity going forward, exactly like `bulls`/`bears` accruing value tied to a transferable position address in the original report.

Both fee-collection paths become permanently unusable once `pool_creator == Pubkey::default()`:
- `collect_creator_fee` requires the signer to equal `pool_state.pool_creator`, which is impossible for the zero address (no keypair exists for it): [4](#0-3) 
- `collect_creator_fee_permissionless` sends fees to an ATA whose authority is `pool_state.pool_creator` (zero address); tokens land in an account no one can ever move because no private key exists for that authority: [5](#0-4) [6](#0-5) 

By contrast, the regular `initialize` instruction requires `creator: Signer<'info>`, which cannot be satisfied by the zero address, so this issue is specific to `initialize_with_permission`. [7](#0-6) 

### Impact Explanation
Once a pool is initialized with `pool_creator = Pubkey::default()`, every subsequent swap through that pool accrues `creator_fees_token_0`/`creator_fees_token_1` that can never be collected by anyone — they remain in the pool vault, excluded from swappable balances by `vault_amount_without_fee`, effectively a permanent freeze of the accrued creator-fee portion of trading fees. This is a permanent, unrecoverable loss of value analogous to the report's "assets stuck in the contract."

### Likelihood Explanation
Reachable in a single transaction by any account holding a valid `permission` PDA (an unprivileged, non-admin pool creator per the in-scope actor set) simply by passing `Pubkey::default()` (or any other un-owned pubkey) as the `creator` account when calling `initialize_with_permission`. No collusion or special conditions are required.

### Recommendation
Add a constraint on `creator` (or a runtime check in `initialize_with_permission`) requiring `creator.key() != Pubkey::default()`, mirroring the `require_keys_neq!` checks already used elsewhere in the codebase (e.g., `set_new_protocol_owner`/`set_new_fund_owner` in `update_config.rs`). [8](#0-7) 

### Proof of Concept
1. Attacker obtains a valid `Permission` PDA for their `payer` key (via whatever legitimate flow grants `initialize_with_permission` permission).
2. Attacker calls `initialize_with_permission`, supplying `creator = Pubkey::default()` (the all-zero pubkey / System Program ID) as the `creator` account — no signature is required for this account since it is an `UncheckedAccount`.
3. `pool_state.pool_creator` is set to `Pubkey::default()`.
4. Any swaps through this pool accrue `creator_fees_token_0`/`creator_fees_token_1`.
5. `collect_creator_fee` can never succeed (`address = pool_state.pool_creator` constraint requires a signer matching the zero address, impossible).
6. `collect_creator_fee_permissionless` can be called by anyone, but the fees are transferred into an ATA owned by the zero address, permanently inaccessible since no private key exists for that pubkey — the fees are irrecoverably locked.

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

**File:** programs/cp-swap/src/states/pool.rs (L134-153)
```rust
    pub fn initialize(
        &mut self,
        auth_bump: u8,
        lp_supply: u64,
        open_time: u64,
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
        self.token_0_vault = token_0_vault;
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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L61-69)
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

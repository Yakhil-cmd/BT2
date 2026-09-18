Confirmed: `pool_state.initialize()` at [1](#0-0)  stores `pool_creator` with no zero-address validation, and `initialize_with_permission` passes an arbitrary, non-signing `creator: UncheckedAccount<'info>` into that field with no `require_keys_neq!` check.

### Title
Pool creator can be set to `Pubkey::default()` (address(0)) in `initialize_with_permission`, permanently locking accrued creator fees - (File: programs/cp-swap/src/instructions/initialize_with_permission.rs)

### Summary
`initialize_with_permission` lets the calling `payer` specify an arbitrary `creator: UncheckedAccount<'info>` (not a `Signer`) that is stored unchecked as `PoolState.pool_creator`. No check exists to reject `Pubkey::default()` (all-zero pubkey / the System Program's address), analogous to `MeritDutchAuction::setNft` allowing the NFT contract to be set to `address(0)` without validation.

### Finding Description
In `InitializeWithPermission`, `creator` is declared as an `UncheckedAccount` with no signer requirement and no constraint tying it to `payer` or any other account: [2](#0-1) . Its raw key is passed straight into `pool_state.initialize(...)`: [3](#0-2) , which stores it verbatim with no zero-address check: [1](#0-0) .

Compare this to `update_amm_config`'s `set_new_protocol_owner`/`set_new_fund_owner`, which explicitly guard against this exact bug class with `require_keys_neq!(new_owner, Pubkey::default())`: [4](#0-3) . No equivalent guard exists for `pool_creator` in `initialize_with_permission`.

Once `pool_creator == Pubkey::default()`:
- `collect_creator_fee` requires `creator: Signer<'info>` with `address = pool_state.load()?.pool_creator`: [5](#0-4) . No keypair exists for the default/System Program pubkey, so this instruction can never be signed and always reverts.
- `collect_creator_fee_permissionless` still succeeds for anyone, but sends the accumulated `creator_fees_token_0`/`creator_fees_token_1` to an ATA whose authority is `Pubkey::default()`: [6](#0-5) [7](#0-6) . Because that address has no controlling private key, funds transferred there are permanently unrecoverable.

### Impact Explanation
This permanently freezes all accrued creator fees for the pool: `collect_creator_fee` reverts forever, and `collect_creator_fee_permissionless` irreversibly sends the funds to an address nobody controls. This matches the accepted impact criteria (permanent freezing / loss of funds), directly analogous to the reported bug where an unchecked address-to-zero assignment breaks a core user-facing flow.

### Likelihood Explanation
`initialize_with_permission` requires only that `payer` hold a valid `permission` PDA (a pool-creation permission, not the protocol admin) [8](#0-7) ; nothing else constrains the `creator` account. Any permissioned pool creator (accidentally or deliberately) can pass `Pubkey::default()` (or any unrelated address they don't control) as `creator` in a single transaction, with no additional cost or privilege required beyond normal pool creation.

### Recommendation
Add an explicit check in `initialize_with_permission` (mirroring the existing `require_keys_neq!(new_owner, Pubkey::default())` pattern used in `update_config.rs`) to reject `creator == Pubkey::default()` before calling `pool_state.initialize(...)`, e.g.:
```rust
require_keys_neq!(ctx.accounts.creator.key(), Pubkey::default());
```

### Proof of Concept
1. Obtain a valid `permission` PDA for `payer` (as required by `InitializeWithPermission`).
2. Call `initialize_with_permission` passing `creator = Pubkey::default()` (`11111111111111111111111111111111`) along with otherwise valid mints/vaults/amounts.
3. The pool is created successfully; `PoolState.pool_creator` is now `Pubkey::default()`.
4. Swaps occur and `creator_fees_token_0`/`creator_fees_token_1` accrue in `PoolState`.
5. Any call to `collect_creator_fee` reverts because no `Signer` can ever match `address = Pubkey::default()`.
6. Anyone calls `collect_creator_fee_permissionless`; it succeeds and transfers the accrued fees into an ATA owned by `Pubkey::default()`, permanently locking those funds since no private key exists for that address.

### Citations

**File:** programs/cp-swap/src/states/pool.rs (L151-152)
```rust
        self.amm_config = amm_config.key();
        self.pool_creator = pool_creator.key();
```

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

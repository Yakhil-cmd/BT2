### Title
Unvalidated `pool_creator` address (including the zero/default `Pubkey`) permits permanent burning of accumulated creator fees via `collect_creator_fee_permissionless` - ([File: programs/cp-swap/src/instructions/initialize_with_permission.rs])

### Summary
`initialize_with_permission` accepts an arbitrary, unchecked `creator` account and stores it verbatim as `pool_state.pool_creator` with no validation that it is a real, controllable address. `collect_creator_fee_permissionless` is intentionally callable by any unprivileged party and always routes accumulated creator fees to the ATA of `pool_state.pool_creator`. If `pool_creator` is the Solana "zero"/default `Pubkey` (or any other address nobody controls the private key for), any unprivileged caller can trigger `collect_creator_fee_permissionless` and permanently burn the pool's accumulated creator fees, exactly mirroring the reported pattern where `feeRecipient == address(0)` combined with a permissionless `withdrawFees()` burns fees irrecoverably.

### Finding Description
In `initialize_with_permission`, the `creator` account is declared as an `UncheckedAccount` with no ownership or address constraint: [1](#0-0) 

Its raw key is stored unchecked into `PoolState.pool_creator` in `pool_state.initialize(...)`: [2](#0-1) 

and in `PoolState::initialize`: [3](#0-2) 

There is no check anywhere rejecting `Pubkey::default()` (Solana's canonical "no owner" address, analogous to `address(0)` in Solidity) or any other address that nobody holds the signing key for.

`collect_creator_fee_permissionless` is explicitly designed so that "anyone can trigger the collection since the fee is always sent to the pool creator" — the `payer` need not be the creator, and the destination ATA is derived purely from `pool_state.pool_creator`: [4](#0-3) [5](#0-4) 

The instruction unconditionally transfers all pending `creator_fees_token_0`/`creator_fees_token_1` out of the vaults to that ATA and zeroes the pool's fee counters: [6](#0-5) 

If `pool_creator == Pubkey::default()` (or any other address with no known private key), the ATA created by `init_if_needed` at `associated_token::authority = creator` is an account whose authority nobody can ever sign for. Once the fee tokens land there, they are permanently unrecoverable — functionally identical to the reported `feeRecipient = address(0)` burn: an unprivileged action (`collect_creator_fee_permissionless`) sends value to an address that has no private key, with no guard rejecting that destination beforehand.

### Impact Explanation
This causes permanent, irrecoverable loss ("burning") of the pool's accumulated creator fee tokens — real SPL token value transferred out of the pool's vaults into an unspendable account. Because the collection function is deliberately permissionless, any party (not just the pool creator) can trigger the irrecoverable transfer once the zero/default creator address is set, and this can be repeated every time creator fees accrue, continuously destroying value for as long as the pool operates. This matches the Medium severity classification of the original report: value is not stolen by an attacker's own benefit, but destroyed/frozen forever due to a missing zero-address check combined with a permissionless withdrawal path.

### Likelihood Explanation
`initialize_with_permission`'s `creator` field is fully attacker/payer-controlled with zero validation, so setting it to `Pubkey::default()` requires no special privilege beyond calling the pool-creation instruction (which any permissioned payer can do, or which could happen by an honest mistake, e.g., a client passing an uninitialized/default pubkey). Once such a pool exists, triggering the burn only requires a single permissionless call to `collect_creator_fee_permissionless` with attacker-chosen accounts, which anyone can submit. No elevated privileges, races, or complex preconditions are needed.

### Recommendation
Add a validation constraint rejecting `Pubkey::default()` (and ideally requiring `creator` to be a plausible, non-degenerate address) when initializing the pool in `initialize_with_permission`'s `Initialize`/`InitializeWithPermission` accounts struct, e.g.:
```rust
#[account(constraint = creator.key() != Pubkey::default() @ ErrorCode::InvalidCreator)]
pub creator: UncheckedAccount<'info>,
```
Additionally, consider adding a defensive check in `collect_creator_fee_permissionless` (and `collect_creator_fee`) that `pool_state.pool_creator != Pubkey::default()` before transferring, so that even pre-existing pools cannot have their creator fees burned.

### Proof of Concept
1. A payer holding a valid `Permission` PDA calls `initialize_with_permission`, passing `creator = Pubkey::default()` (or any other address with no known keypair) as the unchecked `creator` account.
2. `pool_state.initialize(...)` stores `pool_creator = Pubkey::default()` with no rejection. [7](#0-6) 
3. Swaps occur on the pool, accruing `creator_fees_token_0`/`creator_fees_token_1` in `pool_state` per the fee-split logic.
4. Any unprivileged user (attacker or bystander) calls `collect_creator_fee_permissionless`, supplying `creator = Pubkey::default()`; the instruction creates (`init_if_needed`) `creator_token_0`/`creator_token_1` ATAs owned by `Pubkey::default()` and transfers all accrued creator fees there. [8](#0-7) 
5. Because no private key exists for `Pubkey::default()`, the transferred tokens are permanently unrecoverable — the fees are burned, and this can be repeated for every future fee accrual cycle.

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L11-20)
```rust
pub struct CollectCreatorFeePermissionless<'info> {
    /// Anyone can trigger the collection since the fee is always sent to the pool creator,
    /// the payer only funds the creation of the creator's token accounts if they don't exist yet.
    #[account(mut)]
    pub payer: Signer<'info>,

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-127)
```rust
pub fn collect_creator_fee_permissionless(
    ctx: Context<CollectCreatorFeePermissionless>,
) -> Result<()> {
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    let creator_fees_token_0 = pool_state.creator_fees_token_0;
    let creator_fees_token_1 = pool_state.creator_fees_token_1;
    if creator_fees_token_0 == 0 && creator_fees_token_1 == 0 {
        return err!(ErrorCode::NoFeeCollect);
    }

    let signer_seeds: &[&[u8]] = &[crate::AUTH_SEED.as_bytes(), &[ctx.bumps.authority]];

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.creator_token_0.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        ctx.accounts.token_0_program.to_account_info(),
        creator_fees_token_0,
        ctx.accounts.vault_0_mint.decimals,
        &[signer_seeds],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.creator_token_1.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        ctx.accounts.token_1_program.to_account_info(),
        creator_fees_token_1,
        ctx.accounts.vault_1_mint.decimals,
        &[signer_seeds],
    )?;

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```

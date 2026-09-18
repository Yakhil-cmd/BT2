### Title
Missing non-zero/validity check on the `creator` account in `initialize_with_permission` permanently locks pool creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` accepts an arbitrary, unchecked `creator` account and stores it verbatim as `pool_state.pool_creator` with no validation that the address is non-default/controllable. Because later fee-collection logic (`collect_creator_fee`) requires a `Signer` whose key equals `pool_creator`, and `collect_creator_fee_permissionless` sends the accumulated creator fees to an associated-token-account owned by that same address, setting `creator` to `Pubkey::default()` (or any address with no known private key) permanently locks all accrued creator fees for that pool. This mirrors the reported bug class: an address parameter accepted in an initialization routine without a non-zero/validity check, making a critical role in the contract permanently unusable.

### Finding Description
In `Initialize​WithPermission`, `creator` is declared purely as: [1](#0-0) 
with no `address`, `constraint`, or ownership check, unlike `payer` (a `Signer`) or other accounts elsewhere in the struct. The value is copied straight into pool state via `pool_state.initialize(...)`: [2](#0-1) 
which sets `self.pool_creator = pool_creator.key();` in `PoolState::initialize`: [3](#0-2) 

Downstream, `collect_creator_fee` requires the `creator` account to be a signer whose pubkey matches `pool_state.pool_creator`: [4](#0-3) 

And `collect_creator_fee_permissionless` routes fees to an ATA owned by `pool_creator` regardless of whether that address is controllable: [5](#0-4) [6](#0-5) 

If `creator` is set to `Pubkey::default()` (the all-zero/System Program address) or any other address with no corresponding keypair, no one can ever produce a valid `Signer` matching `pool_creator`, so `collect_creator_fee` can never be invoked successfully. `collect_creator_fee_permissionless` will still succeed in moving fee funds into an ATA owned by that unowned address, but since no private key exists for that owner, the tokens in that ATA can never be transferred out by anyone (SPL/Token-2022 transfers require the token account authority to sign). The creator-fee portion of every subsequent swap in that pool is therefore permanently and irrecoverably locked.

### Impact Explanation
Creator fees are a real economic value split out of every swap's fee (via `creator_fee_on`/`enable_creator_fee`), analogous to LP/protocol funds. Setting an uncontrollable `creator` address permanently freezes those accumulated funds with no recovery path — matching the "permanent freezing of user or LP funds" bar for validity. This is a Medium/High-severity accounting/freezing bug, not merely a best-practice nit, because it results in concrete, unrecoverable loss of fee funds for that pool.

### Likelihood Explanation
`initialize_with_permission` is reachable by any account holding a valid `permission` PDA (a "permissioned" pool creator), who fully controls all instruction inputs including the `creator` account, since it is an `UncheckedAccount` with no address/ownership constraint. A permissioned creator (or anyone who compromises/misuses that role) can trivially pass `Pubkey::default()` or any other uncontrolled key as `creator` in a single transaction at pool-creation time — no unusual conditions or races are required.

### Recommendation
Add a validation constraint on `creator` in `InitializeWithPermission`, e.g. `constraint = creator.key() != Pubkey::default() @ ErrorCode::InvalidCreator`, and/or require `creator` to be a `Signer` (as done in the non-permissioned `initialize` path where `creator` is the payer/signer) so that the stored `pool_creator` is guaranteed to correspond to a real, controllable keypair before pool state is initialized.

### Proof of Concept
1. Attacker/permissioned account obtains a valid `permission` PDA (via `create_permission_pda`) allowing use of `initialize_with_permission`.
2. Attacker calls `initialize_with_permission`, supplying `payer` = self (signer), and `creator` = `Pubkey::default()` (or any address they don't control), along with valid mints/vaults.
3. `pool_state.pool_creator` is set to the zero address per `PoolState::initialize`, `programs/cp-swap/src/states/pool.rs:134-152`.
4. Users swap against the pool; creator fees accrue into `pool_state.creator_fees_token_0/1`.
5. `collect_creator_fee` can never be called (no signer can match `pool_creator = Pubkey::default()`), `programs/cp-swap/src/instructions/collect_creator_fee.rs:10-13`.
6. Anyone can call `collect_creator_fee_permissionless`, which creates an ATA with `authority = creator` (the zero address) and transfers the accrued fees into it, `programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs:61-79`; those tokens are now permanently unspendable since no private key exists for the zero address.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L26-27)
```rust
    /// CHECK: creator of pool
    pub creator: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L344-359)
```rust
        )?;
        invoke(
            &spl_token::instruction::sync_native(
                ctx.accounts.token_program.key,
                &ctx.accounts.create_pool_fee.key(),
            )?,
            &[
                ctx.accounts.token_program.to_account_info(),
                ctx.accounts.create_pool_fee.to_account_info(),
            ],
        )?;
    }

    pool_state.initialize(
        ctx.bumps.authority,
        liquidity,
```

**File:** programs/cp-swap/src/states/pool.rs (L134-152)
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

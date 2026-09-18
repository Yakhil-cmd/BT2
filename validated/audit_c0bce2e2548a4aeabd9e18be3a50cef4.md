### Title
Missing zero-address (default `Pubkey`) validation on `creator` in `initialize_with_permission` permanently locks accrued creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` accepts a `creator` account that is only declared as `UncheckedAccount<'info>` with no constraint preventing it from being the Solana "zero address" (`Pubkey::default()`, which is identical to the System Program ID and has no discoverable private key). This address is written verbatim into `PoolState.pool_creator`, and the instruction unconditionally sets `enable_creator_fee = true`, so trade fees begin accruing to `creator_fees_token_0/1`. Because no keypair exists for the default `Pubkey`, `collect_creator_fee` can never be signed for such a pool, and `collect_creator_fee_permissionless` will transfer the accrued fees into an associated-token-account owned by the zero address, permanently freezing those funds.

### Finding Description
In `InitializeWithPermission`, `creator` has no ownership/signature/non-default constraint: [1](#0-0) 

That raw value is passed straight into `PoolState::initialize`, which stores it unconditionally as `pool_creator`: [2](#0-1) [3](#0-2) 

Note `enable_creator_fee` is hard-coded to `true` for pools created through this path (final argument `true` at line 371), unlike `initialize.rs` which passes `false`. Once the pool is trading, creator fees accumulate in `pool_state.creator_fees_token_0/1`.

Two collection paths exist:
- `collect_creator_fee` requires the `creator` account to be a `Signer` whose address equals `pool_state.pool_creator`: [4](#0-3) 
If `pool_creator == Pubkey::default()`, no one can ever produce a valid signature for this address, so this instruction can never succeed for the pool.

- `collect_creator_fee_permissionless` does not require the `creator` to sign; it only checks the address matches `pool_state.pool_creator`, and creates/uses an associated token account owned by that (unsigned) `creator` address, funded by an arbitrary `payer`: [5](#0-4) [6](#0-5) 

This instruction will successfully move the fees out of the vaults into ATAs whose authority is the default `Pubkey` (the System Program ID): [7](#0-6) 

Because the System Program address is not backed by any keypair, tokens sent to an account with that authority can never be transferred out by any actor — the program provides no sweep/recovery path for this case.

This is the direct analog of the reported bug class: the guard conditions around a critical identity field (`pool_creator` / proposal address) do not reject the "zero address," leading to funds becoming unreachable/misaccounted.

### Impact Explanation
Creator trading fees that accrue on an `initialize_with_permission`-created pool with `creator == Pubkey::default()` become permanently frozen: `collect_creator_fee` can never be signed, and `collect_creator_fee_permissionless` moves the funds into a token account that nobody can ever control or withdraw from. This is a permanent, protocol-level loss of accrued creator fees for every swap that occurs on the affected pool for as long as it operates, growing over time.

### Likelihood Explanation
Reaching `initialize_with_permission` requires the caller to be a `payer` that already holds a valid `Permission` PDA (granted by the protocol admin) — this matches the "pool creator" actor explicitly listed as an unprivileged-but-reachable entry point in scope. Once permissioned, that pool creator fully controls the `creator` account field passed to the instruction and can trivially set it to `Pubkey::default()` (or any other un-controllable address), either by mistake or intentionally to grief the pool/protocol. No other privileged signer or off-chain condition is needed to trigger the fee lock.

### Recommendation
Add an explicit constraint rejecting the default `Pubkey` for `creator` in `InitializeWithPermission` (and defensively in `Initialize` as well, even though `creator` there is already a required signer), e.g. `constraint = creator.key() != Pubkey::default() @ ErrorCode::InvalidInput`. Consider also validating in `collect_creator_fee_permissionless`/`collect_creator_fee` that `pool_state.pool_creator != Pubkey::default()` as defense in depth for any pools already created with this value.

### Proof of Concept
1. A permissioned pool creator (holder of a `Permission` PDA obtained via `create_permission_pda`) calls `initialize_with_permission`, passing `creator = Pubkey::default()` (System Program ID) along with valid mints, vaults, and other required accounts.
2. `pool_state.pool_creator` is set to `Pubkey::default()` and `enable_creator_fee = true` [2](#0-1) .
3. Users perform `swap_base_input`/`swap_base_output` on this pool; trade fees accumulate into `pool_state.creator_fees_token_0/1`.
4. Anyone calls `collect_creator_fee_permissionless`, supplying `creator = Pubkey::default()`; the instruction creates ATAs owned by the default pubkey and transfers the accumulated `creator_fees_token_0/1` into them [7](#0-6) .
5. The tokens now sit in a token account whose authority is the System Program address; no transaction can ever produce a valid signature for that authority, so the funds are permanently unrecoverable. Attempting `collect_creator_fee` instead fails permanently since no `Signer` can match `pool_creator == Pubkey::default()` [4](#0-3) .

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

**File:** programs/cp-swap/src/states/pool.rs (L151-153)
```rust
        self.amm_config = amm_config.key();
        self.pool_creator = pool_creator.key();
        self.token_0_vault = token_0_vault;
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L11-13)
```rust
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L14-20)
```rust
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

### Title
Missing zero/default-address validation on `creator` in `initialize_with_permission` permanently freezes creator fees - ([File: programs/cp-swap/src/instructions/initialize_with_permission.rs])

### Summary
`InitializeWithPermission` accepts an arbitrary, completely unchecked `creator` account and stores its raw pubkey as `pool_state.pool_creator` with no validation that it is non-zero, non-default, or otherwise a controllable/claimable address, exactly analogous to the reported Convex `Booster.addPool` bug where `_gauge` is never checked against `address(0)` before being persisted and later relied upon by dependent logic (`StashFactory`).

### Finding Description
In `initialize_with_permission.rs` the `creator` account is declared as a bare `UncheckedAccount<'info>` with only a `/// CHECK: creator of pool` comment and no `constraint`, `address`, or non-default check: [1](#0-0) 

Its raw key is passed straight into `pool_state.initialize(...)`: [2](#0-1) 

which unconditionally stores it as `pool_creator` without any zero-check: [3](#0-2) 

This value is later trusted by `collect_creator_fee_permissionless`, which constrains the `creator` account only by equality to the stored (unvalidated) `pool_creator`, and then creates/derives an associated token account with that pubkey as the authority to receive the accumulated creator fees: [4](#0-3) [5](#0-4) 

Because `pool_creator` is never checked to be a meaningful/claimable pubkey (e.g. `Pubkey::default()` or the System Program ID, neither of which has a corresponding private key), a pool creator can initialize a pool with `creator = 11111111111111111111111111111111` (or any other unclaimable pubkey). The ATA that permissionlessly receives creator fees will then be owned by an authority nobody can ever sign for.

### Impact Explanation
`collect_creator_fee_permissionless` is callable by anyone at any time and will keep routing the pool's accrued `creator_fees_token_0`/`creator_fees_token_1` (tracked in `PoolState`, decremented from the pool's fee ledger) into an ATA whose authority is an unclaimable/default pubkey: [6](#0-5) 
This constitutes permanent freezing of creator-fee funds withdrawn from the pool's fee ledger — the funds leave the protocol's accounting but can never be recovered by anyone, matching the "permanent freezing of user or LP funds" impact class.

### Likelihood Explanation
This is fully attacker(pool-creator)-reachable in a single transaction: the pool creator simply supplies `Pubkey::default()`/System Program ID as the `creator` account when calling `initialize_with_permission` (an instruction explicitly in scope as reachable by an unprivileged pool creator). No special privileges beyond calling the pool-creation instruction are required to set this bad value, since the field has zero validation.

### Recommendation
Add an explicit non-default check on `creator` in `initialize_with_permission.rs`, e.g. `require_keys_neq!(ctx.accounts.creator.key(), Pubkey::default())`, and consider also rejecting other well-known unclaimable authorities (System Program ID, Token Program IDs) before persisting `pool_creator` in `PoolState::initialize`.

### Proof of Concept
1. Attacker (as an approved permissioned payer) calls `initialize_with_permission` with all valid mint/vault/config accounts but sets the `creator` account to `Pubkey::default()` (`11111111111111111111111111111111`).
2. `pool_state.initialize(...)` stores `pool_creator = 11111111111111111111111111111111` with no validation.
3. Over time the pool accrues `creator_fees_token_0`/`creator_fees_token_1`.
4. Anyone calls `collect_creator_fee_permissionless`; the `creator` account constraint (`address = pool_state.load()?.pool_creator`) is trivially satisfied by passing `11111111111111111111111111111111`, and `creator_token_0`/`creator_token_1` ATAs are created with `authority = creator` (the default pubkey).
5. Fees are transferred out of the pool vaults into these ATAs, decreasing `creator_fees_token_0/1` in `PoolState`, but the funds are now permanently unclaimable since no keypair exists for the default pubkey.

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

**File:** programs/cp-swap/src/states/pool.rs (L175-176)
```rust
        self.creator_fees_token_0 = 0;
        self.creator_fees_token_1 = 0;
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

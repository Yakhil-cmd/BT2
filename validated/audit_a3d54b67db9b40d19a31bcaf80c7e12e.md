### Title
Unvalidated `creator` account in `initialize_with_permission` permanently freezes creator trading fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` accepts an arbitrary, unconstrained `creator` account and stores it verbatim as `pool_state.pool_creator` while unconditionally enabling creator fee accrual (`enable_creator_fee = true`). Because `creator` is never validated to be a signable, non-zero/non-degenerate address, a caller can set it to the System Program ID (the all-zero pubkey) or any other address that cannot produce a valid `Signer`, permanently locking all creator fees accrued by that pool.

### Finding Description
`creator` in `InitializeWithPermission` is declared as an `UncheckedAccount<'info>` with no signer or address constraint: [1](#0-0) 

This raw, attacker-controlled `creator` pubkey is passed directly into `pool_state.initialize(...)` and persisted as `pool_creator`, with `enable_creator_fee` hardcoded to `true`: [2](#0-1) 

`PoolState::initialize` stores whatever pubkey is supplied without any zero-address or validity check: [3](#0-2) 

The only way to ever withdraw accumulated `creator_fees_token_0`/`creator_fees_token_1` is `collect_creator_fee`, which requires a `Signer` whose key matches `pool_state.pool_creator`: [4](#0-3) 

If `pool_creator` is set to the System Program ID (`11111111111111111111111111111111`, i.e., the zero-derived address) or any other pubkey with no corresponding private key, no account can ever sign as that key, so `collect_creator_fee` can never succeed for that pool. This is the same root-cause class as the referenced report: a privileged/identity field (`owner`/`creator`) is accepted without a non-zero/validity check in an initialization routine.

By contrast, the permissionless `initialize` instruction correctly types `creator` as a `Signer<'info>`, which forces it to be a real, signable key: [5](#0-4) 

so this issue is specific to `initialize_with_permission`.

### Impact Explanation
Every swap routed through a pool created via `initialize_with_permission` accrues `creator_fees_token_0`/`creator_fees_token_1` in the pool vaults (since `enable_creator_fee` is forced `true`). If `pool_creator` is set to an unsignable address, these accrued fees become permanently stuck in `token_0_vault`/`token_1_vault` — unrecoverable by anyone, including the protocol admin, because `collect_creator_fee` strictly gates on `pool_state.pool_creator` matching the transaction signer. This is a permanent freezing of funds that would otherwise belong to a legitimate pool creator.

### Likelihood Explanation
`initialize_with_permission` is gated by a `Permission` PDA check, so it can only be invoked by allow-listed pool creators rather than an arbitrary public user; however, within that permitted set, no code path prevents an authorized caller from passing a mismatched or degenerate `creator` account (e.g., accidentally or maliciously supplying the System Program address, a burn address, or a mistakenly-derived PDA with no signer). Given `creator` accepts any `UncheckedAccount`, this is straightforward to trigger in a single call.

### Recommendation
Add an explicit constraint ensuring `creator` is a valid, non-zero, and (ideally) signer-capable identity, e.g.:
- Require `creator.key() != Pubkey::default()` (reject System Program/zero address), and/or
- Require `creator` to be a `Signer<'info>` (consistent with the permissionless `initialize` path), or otherwise verify the supplied `creator` account can plausibly sign future transactions before persisting it into `pool_state.pool_creator`.

### Proof of Concept
1. An allow-listed caller obtains a valid `Permission` PDA and calls `initialize_with_permission`, supplying `creator = SystemProgram::id()` (the zero/default pubkey) instead of a real keypair.
2. `pool_state.initialize(...)` stores this value into `pool_state.pool_creator` and sets `enable_creator_fee = true`. [2](#0-1) 
3. Users swap against the pool; `creator_fees_token_0`/`creator_fees_token_1` accumulate in the vaults over time.
4. Anyone attempts `collect_creator_fee`; the `#[account(mut, address = pool_state.load()?.pool_creator)]` constraint on `creator: Signer<'info>` can never be satisfied because no keypair exists for the System Program address, so the instruction always fails. [4](#0-3) 
5. The accrued creator fees remain permanently locked in the pool vaults.

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L10-13)
```rust
pub struct CollectCreatorFee<'info> {
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L22-24)
```rust
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

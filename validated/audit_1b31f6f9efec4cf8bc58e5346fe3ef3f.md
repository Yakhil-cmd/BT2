### Title
Arbitrary, unvalidated `pool_creator` in `initialize_with_permission` permanently freezes accrued creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` lets a permissioned pool creator (`payer`) set an entirely arbitrary `creator: UncheckedAccount<'info>` [1](#0-0)  as the pool's `pool_creator` when calling `pool_state.initialize(...)` [2](#0-1) . This address is never verified to be controllable (it is not required to sign the `initialize_with_permission` transaction, nor checked against any known signer). Once fees accrue to `creator_fees_token_0`/`creator_fees_token_1` on `PoolState` via `update_fees` during swaps [3](#0-2) , the only way to move them out of the vault is `collect_creator_fee` (requires `pool_creator` to be a `Signer`) [4](#0-3)  or `collect_creator_fee_permissionless` (sends the tokens to an ATA owned by `pool_creator`, callable by anyone) [5](#0-4) .

### Finding Description
If the address supplied as `creator` has no corresponding private key (e.g. a PDA of an unrelated program, the pool's own vault/authority address, or any address the payer does not actually control), the resulting `pool_creator` can never sign a transaction. This permanently disables `collect_creator_fee`. The only remaining path, `collect_creator_fee_permissionless`, does not require `pool_creator` to sign — it simply creates an ATA owned by that address and transfers the accumulated `creator_fees_token_0`/`creator_fees_token_1` into it [6](#0-5) . Because the owning address has no controlling signer, tokens delivered to that ATA become permanently unrecoverable by anyone — there is no sweep or recovery mechanism in the program, mirroring the reported bug class where an accounting entry is severed from any party capable of claiming it, leaving the underlying tokens stuck forever.

### Impact Explanation
This permanently and irrecoverably locks the "creator fee" portion of trading fees collected by the pool (a real economic value skimmed from every swap for the lifetime of the pool), with no path for governance, the pool creator, or any user to recover them. This is a real value-destroying accounting/freezing defect reachable purely through the documented, permissionless `initialize_with_permission` instruction and ordinary `swap_base_input`/`swap_base_output` activity.

### Likelihood Explanation
`initialize_with_permission` is explicitly designed to be called by any account holding a `Permission` PDA (not the protocol admin), and the `creator` field is an `UncheckedAccount` with no constraint tying it to a signer or to `payer` [7](#0-6) . A pool creator could set this by mistake (typo/wrong keypair) or, more importantly, an attacker with permission access could deliberately misconfigure `creator` to permanently sink creator fees, or the value could simply be lost by accident since nothing in the interface signals the risk.

### Recommendation
Require `creator` to be a `Signer` in `initialize_with_permission` (as is already done for the non-permissioned `Initialize` context's `creator`), or otherwise validate that the supplied `pool_creator` is capable of receiving funds it can move (e.g., require it match `payer`, or add an explicit owner-only "sweep"/reassign-creator instruction that lets the protocol reassign `pool_creator` if fees become stuck).

### Proof of Concept
1. An account holding a valid `Permission` PDA calls `initialize_with_permission`, passing `creator = <PDA of some other, unrelated on-chain program>` (or any address with no known private key) while itself signing as `payer`.
2. `pool_state.initialize(...)` stores this address as `pool_creator` [2](#0-1) .
3. Users swap against the pool; `update_fees` accrues nonzero `creator_fees_token_0`/`creator_fees_token_1` [3](#0-2) .
4. `collect_creator_fee` can never succeed because `pool_creator` cannot produce a valid signature [4](#0-3) .
5. Anyone calls `collect_creator_fee_permissionless`; it succeeds, creating an ATA owned by the unclaimable `pool_creator` and transferring the fee balances there, zeroing `creator_fees_token_0/1` on `pool_state` [8](#0-7) . The tokens now sit in an ATA nobody can ever move, permanently locking that value with no sweep mechanism anywhere in the program.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L20-27)
```rust
#[derive(Accounts)]
pub struct InitializeWithPermission<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub payer: Signer<'info>,

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

**File:** programs/cp-swap/src/states/pool.rs (L326-351)
```rust
    pub fn update_fees(
        &mut self,
        protocol_fee: u64,
        fund_fee: u64,
        creator_fee: u64,
        direction: TradeDirection,
    ) -> Result<()> {
        if !self.enable_creator_fee {
            require_eq!(creator_fee, 0)
        }
        let is_creator_fee_on_input = self.is_creator_fee_on_input(direction)?;
        match direction {
            TradeDirection::ZeroForOne => {
                self.protocol_fees_token_0 = self
                    .protocol_fees_token_0
                    .checked_add(protocol_fee)
                    .unwrap();
                self.fund_fees_token_0 = self.fund_fees_token_0.checked_add(fund_fee).unwrap();

                if is_creator_fee_on_input {
                    self.creator_fees_token_0 =
                        self.creator_fees_token_0.checked_add(creator_fee).unwrap();
                } else {
                    self.creator_fees_token_1 =
                        self.creator_fees_token_1.checked_add(creator_fee).unwrap();
                }
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L9-13)
```rust
#[derive(Accounts)]
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

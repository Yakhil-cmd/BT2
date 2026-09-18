### Title
Unverified `creator` Account in `initialize_with_permission` Permanently Redirects Pool Creator Fee Revenue - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`InitializeWithPermission` accepts a `creator` account that is only an `UncheckedAccount` with no signature requirement, no ownership constraint, and no relationship check to the `payer` or the `permission` PDA. This attacker-chosen address is written directly into `PoolState.pool_creator`, the field that permanently and exclusively controls who can claim all future accumulated creator-swap fees for the pool's lifetime.

### Finding Description
In `InitializeWithPermission`, the `creator` field is declared as: [1](#0-0) 
with no `Signer`, no `address =`, no `constraint =`, and no relation to `payer` (whose only tie is a `permission` PDA derived from `payer.key()`, not `creator.key()`): [2](#0-1) 

The value is passed straight into `pool_state.initialize(...)` as the pool's permanent creator record: [3](#0-2) 

This is analogous to the reported `drawDebt` issue: a function accepts an address parameter that determines who receives privileged benefits (there, borrower credit; here, creator-fee ownership) without verifying that the caller is authorized to act on behalf of that address, or that the address has consented.

`pool_state.pool_creator` subsequently gates who can claim accumulated `creator_fees_token_0`/`creator_fees_token_1` via `CollectCreatorFee`, which enforces `address = pool_state.load()?.pool_creator` on the signer: [4](#0-3) 
and via the permissionless variant which always routes fees to whatever `pool_creator` was recorded: [5](#0-4) 

Because `creator` in `initialize_with_permission` is never validated, whoever holds the required `permission` PDA (i.e., whoever is authorized to call this permissioned entry point on behalf of a real project/token creator) can freely set `creator` to their own wallet instead of the intended creator's wallet, permanently diverting all future creator-fee revenue for that pool away from the legitimate creator.

For comparison, the un-permissioned `Initialize` instruction correctly ties the recorded creator to the actual fee-paying signer: [6](#0-5) [7](#0-6) 
i.e., `pool_creator` is always `creator.key()`, which is a `Signer`. `initialize_with_permission` breaks this invariant by decoupling the recorded `creator` from any signer or verified identity.

### Impact Explanation
`creator_fees_token_0`/`creator_fees_token_1` accrue on every swap for the life of the pool via `update_fees` in `swap_base_input`/`swap_base_output`, and can only ever be withdrawn to the single address stored in `pool_state.pool_creator`. Setting this field to an attacker-controlled address at pool-creation time is a permanent, unrecoverable diversion of fee-ledger accounting: the legitimate project/creator loses all rights to their fee stream for the pool's entire lifetime, while an unauthorized party gains a privileged, permanent claim on those funds. This satisfies the "insolvent pool or fee-ledger accounting" / "unauthorized privileged effect" bar, since it is not merely a griefing issue — it is a durable, one-shot theft of future revenue rights baked into on-chain state that cannot be corrected after pool initialization.

### Likelihood Explanation
Exploitation requires only calling `initialize_with_permission` with an attacker-chosen `creator` account and a valid `permission` PDA for the calling `payer` — no special privilege over the `creator` identity itself is needed since it is never checked. Any party with `permission` access to launch a pool (e.g., a compromised or malicious relayer/integrator in a permissioned launchpad flow) can trivially substitute their own address for the legitimate creator with a single transaction and attacker-chosen accounts/data, matching the report's "single submitted transaction with attacker-chosen accounts and data" bar.

### Recommendation
Require `creator` to be a `Signer` (mirroring `Initialize`), or add an explicit constraint tying `creator` to a verified identity (e.g., require `creator` to sign, or bind `creator` cryptographically to the `permission` PDA/payer relationship) so that only the legitimate token/pool creator — or someone with their explicit authorization — can be recorded as `pool_state.pool_creator`.

### Proof of Concept
1. Attacker (or any party holding a `permission` PDA for their own `payer` key) calls `initialize_with_permission` with:
   - `payer` = attacker's funded wallet (signs, provides `init_amount_0`/`init_amount_1` liquidity and pays fees)
   - `creator` = attacker's second wallet (or attacker's own wallet), an arbitrary `UncheckedAccount` with no signature
2. The instruction succeeds because no constraint validates `creator`: [1](#0-0) 
3. `pool_state.pool_creator` is permanently set to the attacker's chosen address: [3](#0-2) 
4. As users swap through the pool, `creator_fees_token_0`/`creator_fees_token_1` accrue in `pool_state`.
5. Only the attacker's chosen `creator` address can ever collect these fees via `CollectCreatorFee`'s `address = pool_state.load()?.pool_creator` constraint [4](#0-3) , permanently excluding the legitimate/intended creator from any fee revenue.

### Citations

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-24)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L344-349)
```rust
    pool_state.initialize(
        ctx.bumps.authority,
        liquidity,
        open_time,
        ctx.accounts.creator.key(),
        ctx.accounts.amm_config.key(),
```

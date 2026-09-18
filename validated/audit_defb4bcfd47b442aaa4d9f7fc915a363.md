### Title
Unchecked `creator` account in `initialize_with_permission` lets the permissioned payer assign the privileged, fee-earning `pool_creator` role to an arbitrary attacker-chosen address - ([File: programs/cp-swap/src/instructions/initialize_with_permission.rs])

### Summary
`initialize_with_permission` binds the pool's `pool_creator` field (a privileged role that exclusively earns and can withdraw the pool's ongoing creator-fee stream) to whatever pubkey is passed as the `creator` account, with **no signature requirement and no constraint** tying it to the authorized `payer`/`permission` holder. This mirrors the reported bug class: a low-trust caller reaches a state-mutating instruction that writes an attacker-supplied identity into a privileged-role field with no check that the caller is entitled to assign that identity to that role.

### Finding Description
In `InitializeWithPermission`, `creator` is declared as a bare `UncheckedAccount<'info>` with no `constraint`, no `address =`, and no `Signer` requirement: [1](#0-0) 

The only actual authorization gate in this instruction is that a `Permission` PDA must already exist for `payer` (created out-of-band by an admin via `create_permission_pda`): [2](#0-1) 

That `permission.authority` field, however, is never read or compared against `creator` (or anything else) anywhere in the instruction body — it exists only to gate whether the instruction can execute at all, not who may be named `pool_creator`. At the end of the handler, the attacker-controlled `creator` account key is written directly into the pool's privileged role field with zero validation: [3](#0-2) 

Contrast this with the sibling permissionless instruction `initialize`, where `creator` is a `Signer<'info>` and is therefore cryptographically bound to whoever actually funds and calls the instruction: [4](#0-3) [5](#0-4) 

`pool_state.pool_creator` is a high-value privileged field: it is the sole authority permitted to sign and collect accrued creator fees via `collect_creator_fee` (gated by `address = pool_state.load()?.pool_creator`): [6](#0-5) 

and is also the fixed, unconditional payout destination in the permissionless variant `collect_creator_fee_permissionless`, where anyone may trigger payout but funds always flow to whatever `pool_creator` was recorded at pool creation: [7](#0-6) 

Because `creator` is never required to equal `payer` (who is the only cryptographically-verified, permission-gated actor) nor `permission.authority`, the permission grant is not actually enforced on the role being assigned — it only proves *someone* is allowed to spend the create-pool fee and post the initial liquidity, not that they are allowed to name the recipient of all future creator-fee revenue.

### Impact Explanation
`pool_creator` accrues `creator_fees_token_0`/`creator_fees_token_1` from every swap against the pool for its entire lifetime: [8](#0-7) 

Because the instruction never validates `creator` against `payer` or `permission.authority`, a caller holding a valid permission grant for their own wallet can name **any arbitrary pubkey** as `pool_creator`. This is an unauthorized privileged-role assignment: the fee-earning identity of the pool is permanently and irrevocably fixed to a value chosen unilaterally by the payer, with no consent or verification from the party actually intended to hold that permission (whoever `permission.authority` represents in the admin's intent), and no way to correct it afterward (there is no update-pool-creator instruction). This can be used to misattribute all future creator-fee revenue away from the legitimate permission holder, or to grief the pool by naming an address that can never sign (permanently locking the signer-gated `collect_creator_fee` path, though funds remain drainable via the permissionless path to that unintended address).

### Likelihood Explanation
Any caller who already possesses a `Permission` PDA (the only real gate on this instruction) can trivially exploit this in a single transaction by simply passing a different `creator` account than their own `payer` key — no race condition, no additional signatures, and no special accounts beyond what the instruction already requires. The bug is directly reachable from the public `initialize_with_permission` entrypoint with fully attacker-chosen instruction data/accounts.

### Recommendation
Require `creator` to be validated against the actual authorized identity, e.g. constrain it to equal `permission.authority` (or require it to be a `Signer` equal to `payer`, matching the plain `initialize` instruction's pattern):
```rust
/// CHECK: creator of pool, must match the permission grant
#[account(constraint = creator.key() == permission.authority @ ErrorCode::InvalidOwner)]
pub creator: UncheckedAccount<'info>,
```
This ties the privileged `pool_creator` role assignment to the same identity the admin actually authorized via `create_permission_pda`, closing the gap between "who may call this instruction" and "who gets the privileged role."

### Proof of Concept
1. Admin calls `create_permission_pda` with `permission_authority = Alice`, creating a `Permission` PDA at seeds `[PERMISSION_SEED, Alice]` (see `programs/cp-swap/src/instructions/admin/create_permission_pda.rs`).
2. Alice (holding the signer key for `payer = Alice`) calls `initialize_with_permission`, supplying `payer = Alice`, and `creator = Mallory` (an arbitrary pubkey Alice chooses, unrelated to the permission grant).
3. The `permission` account constraint resolves successfully because its seeds are derived from `payer.key()` (`Alice`), satisfying the only real authorization check.
4. `pool_state.initialize(...)` is called with `ctx.accounts.creator.key()` (i.e., `Mallory`) written into `pool_state.pool_creator`, per `programs/cp-swap/src/instructions/initialize_with_permission.rs` lines 357-372.
5. `Mallory` now permanently owns 100% of `collect_creator_fee`/`collect_creator_fee_permissionless` rights over the pool's entire future trading volume, despite never having been granted any permission and never having signed any transaction.

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-24)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L344-359)
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
        CreatorFeeOn::BothToken,
        false,
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

**File:** programs/cp-swap/src/states/pool.rs (L200-212)
```rust
    pub fn vault_amount_without_fee(&self, vault_0: u64, vault_1: u64) -> Result<(u64, u64)> {
        let fees_token_0 = self
            .protocol_fees_token_0
            .checked_add(self.fund_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?;
        let fees_token_1 = self
            .protocol_fees_token_1
            .checked_add(self.fund_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?;
```

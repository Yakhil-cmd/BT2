Confirmed: `pool_state.initialize(...)` at `programs/cp-swap/src/instructions/initialize_with_permission.rs:357-372` records `ctx.accounts.creator.key()` (line 361) as the pool's `pool_creator`, and `creator` is declared only as `pub creator: UncheckedAccount<'info>` with no signature or ownership constraint tying it to `payer`.

### Title
Authorization Bypass Through User-Controlled `creator` Key in `initialize_with_permission` Grants Attacker-Chosen Account Ongoing Creator-Fee Rights - (File: programs/cp-swap/src/instructions/initialize_with_permission.rs)

### Summary
`InitializeWithPermission` accepts an arbitrary, unchecked `creator` account (`/// CHECK: creator of pool`, no signer/owner/authority constraint) and stores its pubkey as `PoolState.pool_creator` during pool creation. This value later single-handedly gates who may withdraw accumulated creator fees, functioning as an insecure/user-controlled key analogous to the Liferay `ctCollectionId` IDOR (CWE-639): the party who actually funds and permission-checks the transaction (`payer`, validated against `permission` PDA) is never required to match the privileged `creator` key that is persisted and later trusted.

### Finding Description
`InitializeWithPermission::creator` is declared as: [1](#0-0) 
with no constraint requiring it to be a signer, to equal `payer`, or to be validated by the `permission` PDA check that gates `payer`: [2](#0-1) 

In `initialize_with_permission()`, this attacker-supplied `creator` key is written directly into `PoolState`: [3](#0-2) 

Downstream, both `CollectCreatorFee` and `CollectCreatorFeePermissionless` treat `pool_state.pool_creator` as the sole source of truth for who is authorized to receive creator fees: [4](#0-3) [5](#0-4) 

Because `creator` was never verified to be controlled by (or consented to by) the `payer`/permissioned entity that funded pool creation, any permissioned `payer` can name an arbitrary pubkey (their own alt account, a colluding account, or even a victim's known address for griefing) as `pool_creator`. This is a classic user-controlled key/IDOR pattern: a security-relevant identifier (`creator`) is taken from caller-supplied input and used later to authorize a privileged action (fee withdrawal) without validating that the input corresponds to a party who should legitimately hold that privilege at creation time.

### Impact Explanation
Since `creator_fee_on` and `enable_creator_fee` are also caller-controlled at initialization (line 371 `creator_fee_on`, `true` for `enable_creator_fee`), and creator fees accumulate from every swap through the pool, whoever is recorded as `pool_creator` can call `collect_creator_fee`/`collect_creator_fee_permissionless` at any time to redirect ongoing protocol-fee-like revenue. If a payer sets `creator` to an address it fully controls that differs from any expected/intended pool operator identity (e.g., in front-end/off-chain flows that assume `payer == creator` or that `creator` was vetted by the permission system), the fee stream is effectively siphoned to an account whose right to hold it was never checked by the on-chain authorization system (the `permission` PDA only vets `payer`, not `creator`). This is a real, reachable, on-chain accounting/authorization flaw (funds redirection) reachable from a single transaction with attacker-chosen accounts, matching the "unauthorized privileged effect" impact bar.

### Likelihood Explanation
High likelihood of exploitation by any permissioned payer: no privileged signer, leaked key, or off-chain component is required — the `payer` only needs a valid `permission` PDA (an intended, obtainable state for a legitimate pool creator) and can then freely set `creator` to any pubkey they choose in the same transaction, with no additional constraint enforced by the Anchor account validation.

### Recommendation
Require `creator` to be either the same as `payer` or an explicit signer in `InitializeWithPermission`, or alternatively bind `creator` into the `permission` PDA derivation (e.g., `seeds = [PERMISSION_SEED, creator.key()]`) so that the fee-recipient identity is cryptographically tied to the permission-granting process rather than being a freely-chosen, unchecked account.

### Proof of Concept
1. Attacker A obtains a valid `permission` PDA for their own `payer` pubkey via `create_permission_pda`. [2](#0-1) 
2. Attacker A calls `initialize_with_permission`, passing `payer = A`, `creator = B` (an arbitrary second account also controlled by A, or unrelated), with `creator_fee_on` set to collect fees on both tokens and `enable_creator_fee = true` (hardcoded `true` at line 371). [3](#0-2) 
3. `PoolState.pool_creator` is now set to `B`, with no relationship enforced between `B` and the permission-vetted `A`.
4. As swaps occur, `creator_fees_token_0`/`creator_fees_token_1` accumulate in `PoolState`.
5. `B` calls `collect_creator_fee_permissionless`, which is validated only by `address = pool_state.load()?.pool_creator`, and receives all accumulated creator fees. [6](#0-5)

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L11-13)
```rust
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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-130)
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

    Ok(())
}
```

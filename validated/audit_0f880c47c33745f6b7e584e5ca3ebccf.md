Confirmed: `pool_state.pool_creator` is set to `ctx.accounts.creator.key()` — an `UncheckedAccount` that is never required to sign and has no address/constraint binding it to `payer` or the `permission` PDA (which is keyed only to `payer`). This is a client-supplied identity that the program later trusts as an authenticated principal, exactly analogous to the `x-headroom-user-id` header issue: the "who owns this" value comes straight from an attacker-controlled field with no cryptographic binding.

### Title
Pool creator identity bound to unsigned, attacker-chosen account in `initialize_with_permission` allows theft of future creator fees - ([File: programs/cp-swap/src/instructions/initialize_with_permission.rs])

### Summary
`InitializeWithPermission::creator` is declared as an `UncheckedAccount` with no `Signer`, `address`, or `has_one` constraint tying it to the transaction's authenticated signer (`payer`) or to the `permission` PDA (which is seeded only by `payer.key()`). [1](#0-0) [2](#0-1) 
This unchecked, client-supplied `creator` key is written directly into `pool_state.pool_creator` at pool initialization. [3](#0-2) 

### Finding Description
The permission check in `InitializeWithPermission` only validates that `payer` owns a `Permission` PDA seeded by `payer.key()`, authorizing `payer` to create a pool. [2](#0-1) 
However, the separate `creator` account — whose pubkey becomes `pool_state.pool_creator`, the entity entitled to all future creator fees for that pool — is never checked to be a signer, never checked to equal `payer`, and never checked against any registry. Any caller who holds a valid `permission` PDA can submit an `initialize_with_permission` transaction naming an arbitrary pubkey (e.g. another legitimate creator's known wallet address, or a pubkey they don't control themselves but want fees routed away from) as `creator`, and the program will happily record it as `pool_creator` without any proof that account authorized or consented to being designated the fee recipient/collector for this specific pool.

This mirrors the CVE analog exactly: an identity field ostensibly meant to represent "the authenticated owner of this resource" is instead taken verbatim from attacker-supplied input with no binding to the actual authenticated principal (the transaction signer). Downstream, `collect_creator_fee` trusts `pool_state.pool_creator` as the sole authorization check for who may collect accrued creator fees (`address = pool_state.load()?.pool_creator`), and `collect_creator_fee_permissionless` sends fees unconditionally to that recorded address. [4](#0-3) [5](#0-4) 
Since the root value that both instructions trust was never authenticated at the point of pool creation, whoever the `payer`/permission-holder chooses to name effectively controls who "owns" the pool's creator-fee stream — decoupled from any real consent or verification, and in a way indistinguishable on-chain from a normal, legitimate pool creation.

### Impact Explanation
`pool_creator` gates a real, ongoing value stream: `collect_creator_fee` and `collect_creator_fee_permissionless` transfer the pool's entire accrued `creator_fees_token_0`/`creator_fees_token_1` balance to whatever address is stored in `pool_state.pool_creator`. [6](#0-5) 
Because that address is set from an unauthenticated field at pool-creation time, a permission-holder can misassign the creator-fee entitlement of a pool to any pubkey of their choosing (including one they later compromise, or one belonging to a party who never agreed to be named), permanently steering future swap-generated creator fees to an unintended recipient — a concrete, ongoing fund-diversion issue for LP/creator fee accounting, not merely a cosmetic labeling bug.

### Likelihood Explanation
Exploitation requires only a valid `permission` PDA (held by whoever the admin authorized to call `initialize_with_permission`) and a single transaction with an attacker-chosen `creator` pubkey — no signature from the named `creator`, no `payer == creator` check, and no other safeguard exists in the account validation. This is trivially reachable by any permissioned pool-creation caller with attacker-chosen accounts and data, matching the required "single submitted transaction" threat model.

### Recommendation
Require `creator` to either be a `Signer` (proving consent) or be constrained with `address = payer.key()` / bound into the `permission` PDA seeds so the recorded `pool_creator` is cryptographically tied to an authenticated party, consistent with the pattern already used in the permissionless `Initialize` instruction where `creator` is a `Signer`. [7](#0-6) 

### Proof of Concept
1. Attacker (or any party holding a `permission` PDA created via `create_permission_pda`, itself gated only by the fixed admin/`create_permission_pda_owner` set) calls `initialize_with_permission` as `payer`. [8](#0-7) 
2. In the instruction's account list, attacker supplies `creator = <arbitrary_pubkey>` (any pubkey, not required to sign, not required to equal `payer`). [1](#0-0) 
3. The instruction completes successfully, and `pool_state.pool_creator` is permanently set to `<arbitrary_pubkey>`. [3](#0-2) 
4. All subsequent swaps against the pool accrue `creator_fees_token_0`/`creator_fees_token_1`, which only `<arbitrary_pubkey>` (or anyone paying gas via the permissionless path, sending to `<arbitrary_pubkey>`) can ever claim via `collect_creator_fee`/`collect_creator_fee_permissionless`, regardless of who actually funded, initialized, or intended to own the pool. [4](#0-3)

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-118)
```rust
pub fn collect_creator_fee(ctx: Context<CollectCreatorFee>) -> Result<()> {
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
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L17-20)
```rust
    /// The pool creator that receives the collected creator fees
    /// CHECK: the address is constrained to the `pool_creator` recorded in `pool_state`
    #[account(address = pool_state.load()?.pool_creator)]
    pub creator: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L21-24)
```rust
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/admin/create_permission_pda.rs (L14-20)
```rust
#[derive(Accounts)]
pub struct CreatePermissionPda<'info> {
    #[account(
        mut,
        constraint = (owner.key() == crate::admin::ID || owner.key() == crate::create_permission_pda_owner::ID) @ ErrorCode::InvalidOwner
    )]
    pub owner: Signer<'info>,
```

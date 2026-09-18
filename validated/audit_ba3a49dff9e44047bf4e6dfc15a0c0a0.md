### Title
Unauthenticated `creator` account lets a permissioned payer hijack the `pool_creator` fee-collection privilege in `initialize_with_permission` - (File: programs/cp-swap/src/instructions/initialize_with_permission.rs)

### Summary
`initialize_with_permission` records whatever pubkey is passed as `creator` into `PoolState.pool_creator`, which is the sole authorization check used later by `collect_creator_fee` / `collect_creator_fee_permissionless` to release all accumulated creator trading fees. The `creator` account is an `UncheckedAccount`, is never required to sign, and is never tied to the `payer` (the account that actually funds the pool and holds the `Permission` PDA that gates the instruction). This is the same bug class as CVE-2024-53916: the policy/authorization decision (who becomes the privileged `pool_creator`) is bound to the wrong, unauthenticated identifier instead of the entity whose permission was actually verified.

### Finding Description
The `permission` check in this instruction only verifies that a `Permission` account exists at `seeds = [PERMISSION_SEED, payer.key()]`: [1](#0-0) 

The `creator` field, however, is a bare `UncheckedAccount` with no signer requirement, no `address =` constraint, and no relationship enforced to `payer` or to the verified `permission` account: [2](#0-1) 

That arbitrary `creator` value is then written straight into `PoolState.pool_creator`: [3](#0-2) 

with `enable_creator_fee` forced to `true`, so creator fee accrual is always active for pools created through this path.

`pool_creator` is the only authorization anchor for collecting all creator fees later: [4](#0-3) 
and even in the "permissionless" variant, the destination of funds is still derived purely from `pool_state.pool_creator`: [5](#0-4) 

By contrast, the ordinary `initialize` instruction correctly binds `creator` to a `Signer` who also supplies the deposit tokens, so the identity is self-consistent: [6](#0-5) 

In `initialize_with_permission`, deposit funds come from `payer_token_0`/`payer_token_1` (owned by `payer`), while the fee-collection privilege is assigned to a completely separate, unverified `creator` pubkey supplied in the same transaction: [7](#0-6) 

### Impact Explanation
Any account holding an admin-granted `Permission` PDA (an integrator/launchpad-style permissioned payer, not necessarily a program admin) can call `initialize_with_permission` and set `creator` to an arbitrary pubkey — including a wallet they control that has no relationship to the token, the liquidity, or the intended pool owner. That pubkey then permanently owns the right to withdraw all `creator_fees_token_0`/`creator_fees_token_1` accrued by the pool via `collect_creator_fee`, and can even redirect those fees to any recipient via `collect_creator_fee_permissionless`. This diverts trading-fee revenue that should accrue to the legitimate pool/token creator to an attacker-chosen address — a concrete, permanent misallocation of protocol-designated funds and an unauthorized privileged effect (illegitimate assignment of the `pool_creator` role).

### Likelihood Explanation
Exploitation requires only that the attacker be one of the payers already holding a `Permission` PDA — an integration-level privilege intentionally granted for pool creation, not full program-admin control. Since `initialize_with_permission` is explicitly a pool-creation entry point reachable with attacker-chosen accounts (`creator` is fully attacker-controlled data in the same transaction), and no additional signature or cross-check is required from the true intended creator, likelihood is high for any permissioned integrator who chooses to abuse it, and the flaw is trivially detectable by inspecting the account constraints.

### Recommendation
Require `creator` to either be a `Signer`, or constrain it with `address = payer.key()` (or another verifiable relation to the already-authenticated `permission`/`payer` accounts), so the identity granted the `pool_creator` privilege is always the same identity whose authorization was actually checked — mirroring the fix pattern for CVE-2024-53916, where the correct ID must be used in the policy-enforcement path.

### Proof of Concept
1. Attacker A obtains a `Permission` PDA for their own `payer` pubkey (either being a legitimately whitelisted integrator, or otherwise satisfying the `Permission` seeds check for `payer`).
2. A calls `initialize_with_permission` for a token pair belonging to project P, supplying `payer = A`, but setting `creator = A` (or any address A controls) instead of P's intended creator address — nothing in `InitializeWithPermission`'s account validation rejects this because `creator` is `UncheckedAccount` with no signer/address constraint: [2](#0-1) 
3. `pool_state.initialize(...)` stores `A` as `pool_creator` with `enable_creator_fee = true`.
4. As swaps occur, `creator_fees_token_0/1` accrue in `PoolState`.
5. A calls `collect_creator_fee`, which only checks `address = pool_state.load()?.pool_creator` (i.e., A itself), and drains all accrued creator fees that should belong to project P's designated creator: [4](#0-3)

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L21-27)
```rust
pub struct InitializeWithPermission<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: creator of pool
    pub creator: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L83-97)
```rust
    /// payer token0 account
    #[account(
        mut,
        token::mint = token_0_mint,
        token::authority = payer,
    )]
    pub payer_token_0: Box<InterfaceAccount<'info, TokenAccount>>,

    /// payer token1 account
    #[account(
        mut,
        token::mint = token_1_mint,
        token::authority = payer,
    )]
    pub payer_token_1: Box<InterfaceAccount<'info, TokenAccount>>,
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

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-24)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

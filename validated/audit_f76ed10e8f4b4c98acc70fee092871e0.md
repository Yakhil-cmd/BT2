### Title
Unvalidated `creator` account in `initialize_with_permission` lets the pool-fee beneficiary be set to an arbitrary, unauthorized address - (File: programs/cp-swap/src/instructions/initialize_with_permission.rs)

### Summary
`initialize_with_permission` records `ctx.accounts.creator.key()` as the pool's permanent `pool_creator` beneficiary, but `creator` is an unconstrained `UncheckedAccount` with no signer requirement, no ownership check, and no relationship enforced to `payer` or to the `permission` PDA that gates the call. This is the same root-cause class as the Sherlock finding: a privileged, forward-looking entitlement (there: `msg.sender`/`domain` in a cross-chain claim; here: `pool_creator`, the address entitled to all future creator fees) is derived from attacker-suppliable data that is never checked against the actual authorizing identity.

### Finding Description
`InitializeWithPermission` gates the instruction on a `permission` PDA derived only from `payer`: [1](#0-0) 

But the `creator` account has no constraint at all: [2](#0-1) 

and it is written directly into permanent pool state as the fee beneficiary: [3](#0-2) 

Contrast this with the permissionless `initialize` instruction, where `creator` is required to be the `Signer` funding the deposit, i.e., beneficiary and funder/authorizer are cryptographically the same entity: [4](#0-3) [5](#0-4) 

`pool_state.pool_creator` is later used as the sole authorization/destination check for collecting accumulated creator fees, for both the permissioned and the anyone-can-trigger permissionless paths: [6](#0-5) [7](#0-6) 

Because `creator` is never required to sign, to equal `payer`, or to be validated against the `permission.authority` field, the account that ends up perpetually entitled to the pool's creator-fee stream is decoupled from whoever actually funds the pool (`payer_token_0`/`payer_token_1`, whose authority is `payer`) and from whoever holds the `permission` grant. This mirrors the Satellite `initiateClaim` flaw: a valid authorization credential (a valid Merkle proof / a valid `permission` PDA) is checked, but the beneficiary field carried in the same call is never tied to that credential, letting the beneficiary be substituted arbitrarily.

### Impact Explanation
`pool_creator` permanently controls all future `creator_fees_token_0`/`creator_fees_token_1` accrued by the pool via `collect_creator_fee`/`collect_creator_fee_permissionless`. Since `creator` is unchecked, any account that a permission-holding `payer` (or code/integration constructing this instruction on a user's behalf) chooses to place in that slot becomes the perpetual recipient of the pool's creator-fee revenue stream, regardless of who actually supplied the initial liquidity or who was intended by the protocol/off-chain permission process to be the legitimate pool creator. This is a permanent misdirection of pool-generated fee revenue to an unauthorized address — a concrete, ongoing financial loss to the intended/legitimate beneficiary, matching the severity class of the reference finding (unauthorized diversion of value to an attacker-chosen party).

### Likelihood Explanation
The `creator` field is fully attacker/caller-controlled account data in a single instruction invocation, with no additional signature, PDA-relation, or on-chain check required beyond deriving the `permission` PDA from `payer`. Any integration, relayer, or party who is delegated permission (the `payer` role) and constructs this instruction can set `creator` to any pubkey, including their own, diverting the pool's creator-fee entitlement away from the intended beneficiary at pool-creation time with no possibility of after-the-fact correction (the field is baked into `PoolState` at `initialize`).

### Recommendation
Add an explicit constraint tying `creator` to a verified identity, e.g.:
- Require `creator` to be a `Signer`, or
- Constrain `creator.key() == permission.authority` (i.e., the entity that was actually granted `permission`), or
- Constrain `creator.key() == payer.key()` if the funder and creator-fee beneficiary are intended to be the same party.

### Proof of Concept
1. `payer` (holder of a valid `permission` PDA keyed to `payer.key()`) submits `initialize_with_permission` with `token_0_mint`/`token_1_mint`/`amm_config` and arbitrary `init_amount_0`/`init_amount_1`, funding the pool from `payer_token_0`/`payer_token_1`.
2. In the same instruction, `payer` sets the `creator` account to an address `X` that had no involvement in funding the pool and is not `payer`.
3. `pool_state.initialize(..., ctx.accounts.creator.key(), ...)` stores `pool_creator = X` permanently (`programs/cp-swap/src/instructions/initialize_with_permission.rs:357-372`).
4. Every subsequent swap on this pool accrues `creator_fees_token_0`/`creator_fees_token_1` to the pool state.
5. Anyone can later call `collect_creator_fee_permissionless`, which is constrained only by `address = pool_state.load()?.pool_creator` (`programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs:17-20`), transferring all accrued creator fees to `X`'s associated token accounts — an address with no legitimate claim to the pool's creator-fee stream.

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
